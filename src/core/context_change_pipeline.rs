//! SQL-backed context change pipeline.
//!
//! SQLite is the durable runtime source of truth. This module owns two
//! protocol-neutral stages plus the loop that alternates them:
//!
//! - pending projection: claim pending facts, run the projector, and commit
//!   their context, time wakes, atomic rows, and intent output in one durable
//!   step.
//! - context delta matching: consume committed need/offer changes and mark the
//!   newly satisfiable facts pending.
//!
//! Fact projection writes pending context changes; context delta matching wakes
//! dependent facts; the two stages alternate until neither makes progress.
//! `submit_fact_to_store` / `purge_fact_from_store` are the durable fact
//! mutations, and `process_due_time_range` turns time into another pending
//! source.

use crate::core::context::{ContextOffer, ContextSet, ContextSetDelta};
use crate::core::context_change_helpers::{
    atomic_row_mutations, context_need_row, context_offer_row, decode_fact_id,
    decode_pending_context_change_row, decode_time_wake_row,
    delete_pending_time_ranges_for_owner_in_tx, insert_fact_and_pending_in_tx,
    insert_pending_owner_in_tx, pending_context_change_rows, pending_time_range_row,
    purge_fact_in_tx, record_intent_in_tx, sqlite_string_error, stored_context_for_owner,
    stored_context_matches, stored_matching_context, stored_pending_time_ranges_for_owner,
    time_wake_row, validate_atomic_row_intents,
};
use crate::core::facts::{Fact, FactId};
use crate::core::intent_pipeline::IntentPipeline;
use crate::core::intents::{Intent, IntentExecution};
use crate::core::matchers::{ContextMatch, ContextMatcher};
use crate::core::projection::{
    run_projection_with_context, ProjectionContext, ProjectionRun, Projector, TimeRange, TimeWake,
    Timeline,
};
use crate::core::store::{Store, TableName};

pub(crate) use crate::core::context_change_helpers::{
    persisted_context, persisted_fact, persisted_facts,
};

pub(crate) const FACTS: TableName = TableName::new("facts");
pub(crate) const CONTEXT_NEEDS: TableName = TableName::new("context_needs");
pub(crate) const CONTEXT_OFFERS: TableName = TableName::new("context_offers");
pub(crate) const TIME_WAKES: TableName = TableName::new("time_wakes");
pub(crate) const PENDING_PROJECTION: TableName = TableName::new("pending_projection");
pub(crate) const PENDING_TIME_RANGES: TableName = TableName::new("pending_time_ranges");
pub(crate) const PENDING_CONTEXT_CHANGES: TableName = TableName::new("pending_context_changes");
pub(crate) const INTENTS: TableName = TableName::new("intents");

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PipelineReport {
    pub projections: usize,
    pub context_matches: usize,
    pub woken_facts: usize,
    pub intents: usize,
}

impl PipelineReport {
    fn merge(&mut self, other: PipelineReport) {
        self.projections += other.projections;
        self.context_matches += other.context_matches;
        self.woken_facts += other.woken_facts;
        self.intents += other.intents;
    }
}

/// Insert a fact and mark it pending in the same transaction.
pub(crate) fn submit_fact_to_store(store: &Store, fact: Fact) -> Result<bool, String> {
    store
        .write_transaction(|tx| insert_fact_and_pending_in_tx(tx, &fact))
        .map_err(|err| format!("submit fact: {err}"))
}

/// Bulk insert facts with one transaction and one pending row per insert.
pub(crate) fn submit_facts_to_store(
    store: &Store,
    facts: impl IntoIterator<Item = Fact>,
) -> Result<usize, String> {
    let facts = facts.into_iter().collect::<Vec<_>>();
    store
        .write_transaction(|tx| {
            let mut inserted = 0;
            for fact in &facts {
                if insert_fact_and_pending_in_tx(tx, fact)? {
                    inserted += 1;
                }
            }
            Ok(inserted)
        })
        .map_err(|err| format!("submit facts: {err}"))
}

/// Remove a fact and all durable runtime state derived from it.
pub(crate) fn purge_fact_from_store(store: &Store, owner: FactId) -> Result<bool, String> {
    store
        .write_transaction(|tx| purge_fact_in_tx(tx, owner))
        .map_err(|err| format!("purge fact: {err}"))
}

/// Commit externally projected offers and clear the completed pending facts.
///
/// Bounded sync commands materialize offers directly from verified rows. This
/// keeps the fact-projection transaction rule: newly visible context and
/// completed pending work commit together.
pub(crate) fn commit_projected_context_offers(
    store: &Store,
    offers: &[ContextOffer],
    completed_fact_ids: &[FactId],
) -> Result<(), String> {
    store
        .write_transaction(|tx| {
            tx.insert_table_rows_in_tx(offers.iter().map(context_offer_row).collect())?;
            tx.delete_table_rows_in_tx(
                PENDING_PROJECTION,
                completed_fact_ids.iter().map(|id| id.to_vec()).collect(),
            )?;
            Ok(())
        })
        .map_err(|err| format!("commit projected context offers: {err}"))
}

/// Turn due time wakes into pending facts plus projection time context.
///
/// Time is another source of context: the fact is marked pending and receives
/// the triggering `TimeRange` when it projects.
pub(crate) fn process_due_time_range(
    store: &Store,
    timeline: Timeline,
    start_exclusive: Option<u64>,
    end_inclusive: u64,
    limit: usize,
) -> Result<usize, String> {
    if limit == 0 {
        return Ok(0);
    }
    let range = TimeRange {
        timeline,
        start_exclusive,
        end_inclusive,
    };
    let mut due = store
        .table_rows(TIME_WAKES)
        .map_err(|err| format!("load time wakes: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_time_wake_row(&key, &value))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|wake| wake.timeline == range.timeline && range.contains(wake.at))
        .collect::<Vec<_>>();
    due.sort_by(|left, right| {
        left.at
            .cmp(&right.at)
            .then_with(|| left.owner.cmp(&right.owner))
            .then_with(|| left.timeline.cmp(&right.timeline))
    });
    due.dedup();
    due.truncate(limit);

    store
        .write_transaction(|tx| {
            let mut inserted = 0usize;
            let mut time_range_rows = Vec::new();
            for wake in &due {
                inserted += insert_pending_owner_in_tx(tx, wake.owner)?;
                time_range_rows.push(pending_time_range_row(wake.owner, &range));
            }
            tx.insert_table_rows_in_tx(time_range_rows)?;
            Ok(inserted)
        })
        .map_err(|err| format!("process due time range: {err}"))
}

/// Drive context delta matching and fact projection until no more work is found.
///
/// The two stages alternate: context changes wake facts; fact projection writes
/// more context changes. The loop stops when neither stage made progress or the
/// projection limit has been reached.
pub(crate) fn process_pending_facts_and_context_changes(
    intent_pipeline: &mut IntentPipeline,
    projector: &impl Projector,
    matchers: &[&dyn ContextMatcher],
    store: &Store,
    allowed_tables: &[TableName],
    limit: usize,
) -> Result<PipelineReport, String> {
    let mut total = PipelineReport::default();

    loop {
        let context_report = process_context_changes(store, matchers, limit)?;
        let context_woke_facts = context_report.woken_facts > 0;
        total.merge(context_report);

        if total.projections >= limit {
            break;
        }

        let projection_report = process_pending_facts(
            intent_pipeline,
            projector,
            matchers,
            store,
            allowed_tables,
            limit - total.projections,
        )?;
        let projected_facts = projection_report.projections > 0;
        total.merge(projection_report);

        if !context_woke_facts && !projected_facts {
            break;
        }
    }

    Ok(total)
}

// === Context delta matching ===

/// Drain pending need/offer changes and wake newly matched facts.
fn process_context_changes(
    store: &Store,
    matchers: &[&dyn ContextMatcher],
    limit: usize,
) -> Result<PipelineReport, String> {
    let mut report = PipelineReport::default();
    if limit == 0 {
        return Ok(report);
    }

    let rows = store
        .table_rows(PENDING_CONTEXT_CHANGES)
        .map_err(|err| format!("load pending context changes: {err}"))?;
    let mut keys = Vec::new();
    let mut delta = ContextSetDelta::default();
    for (key, value) in rows.into_iter().take(limit) {
        let decoded = decode_pending_context_change_row(&key, &value)?;
        keys.push(key);
        delta.added_needs.extend(decoded.added_needs);
        delta.added_offers.extend(decoded.added_offers);
    }
    if keys.is_empty() {
        return Ok(report);
    }
    let commit = commit_context_change_matching(store, keys, &delta, matchers)?;
    report.context_matches += commit.context_matches;
    report.woken_facts += commit.woken_facts;
    Ok(report)
}

struct ContextChangeCommit {
    context_matches: usize,
    woken_facts: usize,
}

/// Commit one batch of pending context changes.
///
/// Deleting the pending-change rows and inserting dependent pending facts are
/// one transaction, so a crash cannot replay already-consumed changes without
/// also preserving the wakeups they produced.
fn commit_context_change_matching(
    store: &Store,
    pending_keys: Vec<Vec<u8>>,
    delta: &ContextSetDelta,
    matchers: &[&dyn ContextMatcher],
) -> Result<ContextChangeCommit, String> {
    store
        .write_transaction(|tx| {
            tx.delete_table_rows_in_tx(PENDING_CONTEXT_CHANGES, pending_keys)?;
            let current_delta = current_stored_context_delta(tx, delta)?;
            let context_matches = stored_context_matches(tx, &current_delta, matchers)
                .map_err(sqlite_string_error)?;
            let mut woken_facts = 0usize;
            for matched in &context_matches {
                if persisted_fact(tx, &matched.need_owner)
                    .map_err(sqlite_string_error)?
                    .is_some()
                {
                    woken_facts += insert_pending_owner_in_tx(tx, matched.need_owner)?;
                }
            }
            Ok(ContextChangeCommit {
                context_matches: context_matches.len(),
                woken_facts,
            })
        })
        .map_err(|err| format!("process pending context change: {err}"))
}

/// Keep only added needs/offers that still exist at commit time.
///
/// A fact may have been purged or reprojected after the pending context-change
/// row was written. Matching against current rows prevents stale wakeups.
fn current_stored_context_delta(
    store: &Store,
    delta: &ContextSetDelta,
) -> rusqlite::Result<ContextSetDelta> {
    let mut current = ContextSetDelta::default();
    for need in &delta.added_needs {
        if store
            .table_row(CONTEXT_NEEDS, &context_need_row(need).key)?
            .is_some()
        {
            current.added_needs.push(need.clone());
        }
    }
    for offer in &delta.added_offers {
        if store
            .table_row(CONTEXT_OFFERS, &context_offer_row(offer).key)?
            .is_some()
        {
            current.added_offers.push(offer.clone());
        }
    }
    Ok(current)
}

// Suppress an unused-import warning while keeping `ContextMatch` named here as
// the context-delta-matching vocabulary this module owns.
type _ContextMatchAlias = ContextMatch;

// === Pending projection ===

/// Process pending facts from SQLite one at a time until there is no work or
/// `limit` facts have completed projection.
///
/// `commit_projection_effects` is the durable boundary: clearing the pending
/// row, replacing context and time wakes, recording the pending context change,
/// applying atomic rows, and recording deferred intents happen together.
/// Ephemeral intents are restart-local and are recorded only after that commit.
fn process_pending_facts(
    intent_pipeline: &mut IntentPipeline,
    projector: &impl Projector,
    matchers: &[&dyn ContextMatcher],
    store: &Store,
    allowed_tables: &[TableName],
    limit: usize,
) -> Result<PipelineReport, String> {
    let mut report = PipelineReport::default();

    for fact_id in pending_owner_batch(store, limit)? {
        if report.projections >= limit {
            break;
        }
        let Some(pending) = load_pending_fact(store, fact_id, matchers)? else {
            store
                .write_transaction(|tx| purge_fact_in_tx(tx, fact_id))
                .map_err(|err| format!("purge stale pending fact: {err}"))?;
            continue;
        };
        let effects = project_fact(intent_pipeline, projector, pending, allowed_tables)?;
        let persisted_intents = commit_projection_effects(store, &effects, allowed_tables)?;

        // Restart-local follow-up runs only after the durable commit succeeds.
        intent_pipeline.remember_fact(effects.fact.clone());
        let mut recorded_ephemeral = 0usize;
        for intent in &effects.ephemeral_intents {
            if intent_pipeline.record_ephemeral_intent(intent.clone())? {
                recorded_ephemeral += 1;
            }
        }
        report.projections += 1;
        report.intents += effects.atomic_intents.len() + persisted_intents + recorded_ephemeral;
    }

    Ok(report)
}

/// Read the next pending fact ids, oldest fact first, without mutating the queue.
fn pending_owner_batch(store: &Store, limit: usize) -> Result<Vec<FactId>, String> {
    let mut owners = Vec::<(u64, FactId)>::new();
    for (key, _) in store
        .table_rows(PENDING_PROJECTION)
        .map_err(|err| format!("load pending projection: {err}"))?
    {
        let owner = decode_fact_id(&key)?;
        let timestamp = persisted_fact(store, &owner)?
            .map(|fact| fact.timestamp)
            .unwrap_or(u64::MAX);
        owners.push((timestamp, owner));
    }
    owners.sort_unstable();
    owners.truncate(limit);
    Ok(owners.into_iter().map(|(_, owner)| owner).collect())
}

/// Load everything projection needs for one fact: its standing context, its due
/// time ranges, and the matched input context exposed to the projector.
fn load_pending_fact(
    store: &Store,
    fact_id: FactId,
    matchers: &[&dyn ContextMatcher],
) -> Result<Option<PendingFact>, String> {
    let Some(fact) = persisted_fact(store, &fact_id)? else {
        return Ok(None);
    };
    let previous_context = stored_context_for_owner(store, &fact_id)?;
    let time_ranges = stored_pending_time_ranges_for_owner(store, &fact_id)?;
    let projection_context =
        stored_matching_context(store, &previous_context, matchers)?.with_time_ranges(time_ranges);
    Ok(Some(PendingFact {
        fact_id,
        fact,
        previous_context,
        projection_context,
    }))
}

/// Run the protocol projector for one fact and split its output by durability.
///
/// No rows are written here. The result is an uncommitted `ProjectionEffects`
/// value that says what should happen if the projection commits.
fn project_fact(
    intent_pipeline: &IntentPipeline,
    projector: &impl Projector,
    pending: PendingFact,
    allowed_tables: &[TableName],
) -> Result<ProjectionEffects, String> {
    let PendingFact {
        fact_id,
        fact,
        previous_context,
        projection_context,
    } = pending;
    let run = run_projection_with_context(projector, &fact, &previous_context, projection_context)?;
    intent_pipeline.validate_intents(&run.intents)?;
    validate_atomic_row_intents(&run.intents, allowed_tables)?;
    Ok(ProjectionEffects::from_run(
        fact_id,
        fact,
        previous_context,
        run,
    ))
}

/// A fact claimed from the pending queue and ready to project.
struct PendingFact {
    fact_id: FactId,
    fact: Fact,
    previous_context: ContextSet,
    projection_context: ProjectionContext,
}

/// The uncommitted output of projecting one pending fact.
struct ProjectionEffects {
    fact_id: FactId,
    fact: Fact,
    previous_context: ContextSet,
    next_context: ContextSet,
    next_time_wakes: Vec<TimeWake>,
    context_delta: ContextSetDelta,
    atomic_intents: Vec<Intent>,
    durable_intents: Vec<Intent>,
    ephemeral_intents: Vec<Intent>,
}

impl ProjectionEffects {
    fn from_run(
        fact_id: FactId,
        fact: Fact,
        previous_context: ContextSet,
        run: ProjectionRun,
    ) -> Self {
        let mut atomic_intents = Vec::new();
        let mut durable_intents = Vec::new();
        let mut ephemeral_intents = Vec::new();
        for intent in run.intents {
            match intent.execution {
                IntentExecution::Atomic => atomic_intents.push(intent),
                IntentExecution::Deferred => durable_intents.push(intent),
                IntentExecution::Ephemeral => ephemeral_intents.push(intent),
            }
        }
        Self {
            fact_id,
            fact,
            previous_context,
            next_context: run.context,
            next_time_wakes: run.time_wakes,
            context_delta: run.context_delta,
            atomic_intents,
            durable_intents,
            ephemeral_intents,
        }
    }
}

/// Commit all durable and atomic projection effects in one SQLite transaction,
/// returning the count of newly persisted deferred intents.
///
/// Ephemeral intents are intentionally absent; they are cached by the caller
/// only after this transaction succeeds.
fn commit_projection_effects(
    store: &Store,
    effects: &ProjectionEffects,
    allowed_tables: &[TableName],
) -> Result<usize, String> {
    store
        .write_transaction(|tx| {
            tx.delete_table_rows_in_tx(PENDING_PROJECTION, vec![effects.fact_id.to_vec()])?;
            delete_pending_time_ranges_for_owner_in_tx(tx, effects.fact_id)?;
            replace_stored_context_owner_rows(
                tx,
                &effects.previous_context,
                &effects.next_context,
            )?;
            replace_stored_time_wake_owner_rows(tx, effects.fact_id, &effects.next_time_wakes)?;
            tx.insert_table_rows_in_tx(pending_context_change_rows(&effects.context_delta))?;

            let (atomic_rows, atomic_deletes) =
                atomic_row_mutations(&effects.atomic_intents, allowed_tables)
                    .map_err(sqlite_string_error)?;
            tx.insert_table_rows_in_tx(atomic_rows)?;
            for delete in atomic_deletes {
                tx.delete_table_rows_in_tx(delete.table, vec![delete.key])?;
            }

            let mut persisted_intents = 0usize;
            for intent in &effects.durable_intents {
                if record_intent_in_tx(tx, intent)? {
                    persisted_intents += 1;
                }
            }
            Ok(persisted_intents)
        })
        .map_err(|err| format!("commit projection effects: {err}"))
}

/// Replace this fact's standing needs/offers using the previous key set.
///
/// Projection owns the complete context set for its fact. Deleting exactly the
/// previous rows avoids wiping rows emitted by other facts with the same role.
fn replace_stored_context_owner_rows(
    store: &Store,
    previous: &ContextSet,
    context: &ContextSet,
) -> rusqlite::Result<()> {
    store.delete_table_rows_in_tx(
        CONTEXT_NEEDS,
        previous
            .needs
            .iter()
            .map(|need| context_need_row(need).key)
            .collect(),
    )?;
    store.delete_table_rows_in_tx(
        CONTEXT_OFFERS,
        previous
            .offers
            .iter()
            .map(|offer| context_offer_row(offer).key)
            .collect(),
    )?;
    store.insert_table_rows_in_tx(context.needs.iter().map(context_need_row).collect())?;
    store.insert_table_rows_in_tx(context.offers.iter().map(context_offer_row).collect())?;
    Ok(())
}

/// Replace all time wakes owned by this fact.
///
/// Projection output is the complete current schedule for the owner, so old
/// rows must disappear when the projection no longer emits them.
fn replace_stored_time_wake_owner_rows(
    store: &Store,
    owner: FactId,
    wakes: &[TimeWake],
) -> rusqlite::Result<()> {
    let delete_keys = store
        .table_rows_with_key_prefix(TIME_WAKES, &owner, usize::MAX)?
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    store.delete_table_rows_in_tx(TIME_WAKES, delete_keys)?;
    store.insert_table_rows_in_tx(wakes.iter().map(time_wake_row).collect())?;
    Ok(())
}
