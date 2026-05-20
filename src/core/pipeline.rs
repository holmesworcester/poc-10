//! SQL-backed runtime pipeline.
//!
//! This module is the whole protocol-neutral runtime: it turns submitted facts
//! into projected context, time wakes, and intents, then dispatches those
//! intents to handlers. SQLite is the durable source of truth; every stage here
//! reads and writes that store. The SQL row encoding underneath lives in
//! [`pipeline_storage`](crate::core::pipeline_storage).
//!
//! # Stages
//!
//! Three stages do all the work:
//!
//! - **Fact projection** ([`process_pending_facts`]) claims a pending fact,
//!   runs the protocol [`Projector`], and commits its context, time wakes,
//!   atomic rows, and intent output.
//! - **Context delta matching** ([`process_context_changes`]) consumes the
//!   need and offer changes projection wrote and marks newly satisfiable facts
//!   pending.
//! - **Intent dispatch** ([`dispatch_deferred_intents`] and its siblings)
//!   claims intents, runs handlers, and commits the facts, purges, atomic rows,
//!   and follow-up intents the handlers emit.
//!
//! Projection and context delta matching feed each other: projecting a fact
//! writes context changes, which wake other facts, which project in turn. They
//! alternate in [`process_pending_facts_and_context_changes`] until neither
//! makes progress. Intent dispatch then drains whatever intents accumulated.
//!
//! # The prepare / commit / finish rhythm
//!
//! Projection and dispatch both process one item at a time in three steps, and
//! reading either stage is mostly a matter of recognizing this shape:
//!
//! 1. **prepare** — pure calculation: run the projector or handler, then
//!    validate and split its output. Touches no rows; yields an uncommitted
//!    "effects" value describing what *should* happen.
//! 2. **commit** — the single SQLite transaction. Every durable effect of the
//!    item lands together, so a crash either replays the whole item or none of
//!    it.
//! 3. **finish** — restart-local follow-up that runs only after the commit
//!    succeeds: update in-memory caches and the [`PipelineReport`].
//!
//! # Durable vs. restart-local state
//!
//! Facts, context needs and offers, time wakes, and deferred and atomic intents
//! all live in SQLite and survive a restart. Ephemeral intents do not: they are
//! deliberately restart-local, held only in [`IntentPipeline`] alongside a fact
//! cache that is a dispatch convenience and never a source of truth. That split
//! is why `finish` is separate from `commit` — restart-local state must not
//! change until the durable transaction has actually committed.
//!
//! # Reading guide
//!
//! The file has three sections, one per stage: fact submission and time
//! triggers, pending-fact projection, and intent dispatch.

use crate::core::context::{diff_context_sets, ContextOffer, ContextSet, ContextSetDelta};
use crate::core::facts::{Fact, FactId};
use crate::core::intents::{
    HandlerContext, HandlerError, HandlerOutput, Intent, IntentExecution, IntentHandler,
};
use crate::core::matchers::{ContextMatch, ContextMatcher};
use crate::core::pipeline_storage::{
    atomic_row_mutations, context_need_row, context_offer_row, decode_fact_id, decode_intent_row,
    decode_pending_context_change_row, decode_time_wake_row,
    delete_pending_time_ranges_for_owner_in_tx, insert_fact_and_pending_in_tx,
    insert_pending_owner_in_tx, intent_row_key, pending_context_change_rows,
    pending_time_range_row, purge_fact_in_tx, record_intent_in_tx, sqlite_string_error,
    stored_context_for_owner, stored_context_matches, stored_matching_context,
    stored_pending_time_ranges_for_owner, time_wake_row, validate_atomic_row_intents,
};
use crate::core::projectors::{
    ProjectionContext, ProjectionOutput, Projector, TimeRange, TimeWake, Timeline,
};
use crate::core::store::{Store, TableName};
use std::collections::BTreeMap;

pub(crate) use crate::core::pipeline_storage::{
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

/// Commit externally projected offers and clear the completed pending facts.
///
/// This is used by bounded sync commands that materialize context offers
/// directly from already-verified rows. It keeps the same transaction rule as
/// fact projection: newly visible context and completed pending work commit
/// together.
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PipelineReport {
    pub projections: usize,
    pub context_matches: usize,
    pub woken_facts: usize,
    pub intents: usize,
}

// === Fact submission, purge, and time triggers ===

/// Insert a fact and mark it pending in the same transaction.
pub(crate) fn submit_fact_to_store(store: &Store, fact: Fact) -> Result<bool, String> {
    let inserted = store
        .write_transaction(|tx| insert_fact_and_pending_in_tx(tx, &fact))
        .map_err(|err| format!("submit fact: {err}"))?;
    Ok(inserted)
}

/// Bulk insert facts with one transaction and one pending row per insert.
pub(crate) fn submit_facts_to_store(
    store: &Store,
    facts: impl IntoIterator<Item = Fact>,
) -> Result<usize, String> {
    let facts = facts.into_iter().collect::<Vec<_>>();
    let inserted = store
        .write_transaction(|tx| {
            let mut inserted = Vec::new();
            for fact in &facts {
                if insert_fact_and_pending_in_tx(tx, fact)? {
                    inserted.push(fact.id);
                }
            }
            Ok(inserted)
        })
        .map_err(|err| format!("submit facts: {err}"))?;
    Ok(inserted.len())
}

/// Remove a fact and all durable runtime state derived from it.
pub(crate) fn purge_fact_from_store(store: &Store, owner: FactId) -> Result<bool, String> {
    let changed = store
        .write_transaction(|tx| purge_fact_in_tx(tx, owner))
        .map_err(|err| format!("purge fact: {err}"))?;
    Ok(changed)
}

/// Turn due time wakes into pending facts plus projection time context.
///
/// Time is modeled as another source of context: the fact is marked pending
/// and receives the triggering `TimeRange` when it projects.
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

    let inserted = store
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
        .map_err(|err| format!("process due time range: {err}"))?;
    Ok(inserted)
}

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
    report.context_matches += commit.context_matches.len();
    report.woken_facts += commit.woken_facts;
    Ok(report)
}

/// Drive context matching and fact projection until no more work is found.
///
/// The two pipelines intentionally alternate: context changes wake facts;
/// fact projection writes more context changes. The loop stops when neither
/// stage made progress or the projection limit has been reached.
pub(crate) fn process_pending_facts_and_context_changes(
    intent_pipeline: &mut IntentPipeline,
    projector: &(impl Projector + ?Sized),
    matchers: &[&dyn ContextMatcher],
    store: &Store,
    allowed_tables: &[TableName],
    limit: usize,
) -> Result<PipelineReport, String> {
    let mut total = PipelineReport::default();

    loop {
        let context_report = process_context_changes(store, matchers, limit)?;
        let context_woke_facts = context_report.woken_facts > 0;
        add_pipeline_report(&mut total, context_report);

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
        add_pipeline_report(&mut total, projection_report);

        if !context_woke_facts && !projected_facts {
            break;
        }
    }

    Ok(total)
}

/// Merge one stage report into the runtime-visible total.
fn add_pipeline_report(total: &mut PipelineReport, report: PipelineReport) {
    total.projections += report.projections;
    total.context_matches += report.context_matches;
    total.woken_facts += report.woken_facts;
    total.intents += report.intents;
}

struct ContextChangeCommit {
    context_matches: Vec<ContextMatch>,
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
                context_matches,
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
        let row = context_need_row(need);
        if store.table_row(CONTEXT_NEEDS, &row.key)?.is_some() {
            current.added_needs.push(need.clone());
        }
    }
    for offer in &delta.added_offers {
        let row = context_offer_row(offer);
        if store.table_row(CONTEXT_OFFERS, &row.key)?.is_some() {
            current.added_offers.push(offer.clone());
        }
    }
    Ok(current)
}

// === Pending-fact projection ===

/// Process pending facts from SQLite one at a time until there is no work or
/// `limit` facts have completed projection.
///
/// This is the readable entry point for the SQL-backed projection path:
///
/// 1. `pending_owner_batch` chooses pending fact ids from SQLite.
/// 2. `load_pending_fact` loads each fact's projection inputs.
/// 3. `process_pending_fact` completes all processing for that one fact.
/// 4. `prepare_projection_effects` runs protocol projection and groups the outputs.
/// 5. `commit_projection_effects` commits every durable/atomic effect in one
///    SQLite transaction.
/// 6. `finish_pending_fact` records restart-local effects and
///    refreshes the report after the transaction has succeeded.
pub(crate) fn process_pending_facts(
    intent_pipeline: &mut IntentPipeline,
    projector: &(impl Projector + ?Sized),
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
        let Some(pending_fact) = load_pending_fact(store, fact_id, matchers)? else {
            store
                .write_transaction(|tx| purge_fact_in_tx(tx, fact_id))
                .map_err(|err| format!("purge stale pending fact: {err}"))?;
            continue;
        };
        process_pending_fact(
            intent_pipeline,
            pending_fact,
            projector,
            store,
            allowed_tables,
            &mut report,
        )?;
    }

    Ok(report)
}

/// Read the next pending fact ids without mutating the queue.
///
/// The commit step removes the row only after projection succeeds. Missing
/// facts are handled by the caller as stale pending rows and purged there.
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

/// Load everything projection needs for one fact.
///
/// `previous_context` is the fact's standing context before this run.
/// `projection_context` is the matched input context exposed to the projector
/// for this run, including any due time ranges.
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

/// Complete all projection work for one pending fact.
///
/// The middle call, `commit_projection_effects`, is the only SQLite
/// transaction in this per-fact pipeline. Everything before it is uncommitted
/// calculation. Everything after it handles restart-local follow-up work that
/// intentionally does not live in SQLite.
fn process_pending_fact(
    intent_pipeline: &mut IntentPipeline,
    pending_fact: PendingFact,
    projector: &(impl Projector + ?Sized),
    store: &Store,
    allowed_tables: &[TableName],
    report: &mut PipelineReport,
) -> Result<(), String> {
    let effects =
        prepare_projection_effects(intent_pipeline, projector, pending_fact, allowed_tables)?;
    let commit = commit_projection_effects(store, &effects, allowed_tables)?;
    finish_pending_fact(intent_pipeline, effects, commit, report)
}

/// Run the protocol projector for one fact and split its output.
///
/// No rows are written here. The result is an uncommitted `ProjectionEffects`
/// value that says what should happen if the projection commits.
fn prepare_projection_effects(
    intent_pipeline: &IntentPipeline,
    projector: &(impl Projector + ?Sized),
    pending_fact: PendingFact,
    allowed_tables: &[TableName],
) -> Result<ProjectionEffects, String> {
    let PendingFact {
        fact_id,
        fact,
        previous_context,
        projection_context,
    } = pending_fact;
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

/// Record restart-local projection output and update the report.
///
/// This function runs after SQLite has accepted the durable work. Ephemeral
/// intents are recorded here because they are deliberately restart-local.
fn finish_pending_fact(
    intent_pipeline: &mut IntentPipeline,
    effects: ProjectionEffects,
    commit: ProjectionCommit,
    report: &mut PipelineReport,
) -> Result<(), String> {
    let intents = effects.atomic_intents.len() + commit.persisted_intents;
    let recorded_ephemeral = record_committed_ephemeral_intents(intent_pipeline, &effects)?;

    report.projections += 1;
    report.intents += intents + recorded_ephemeral;
    Ok(())
}

/// Mirror committed projection state into restart-local intent memory.
///
/// This is deliberately after the SQLite commit: ephemeral intents should only
/// run for a fact whose durable projection effects are visible.
fn record_committed_ephemeral_intents(
    intent_pipeline: &mut IntentPipeline,
    effects: &ProjectionEffects,
) -> Result<usize, String> {
    intent_pipeline.remember_fact(effects.fact.clone());
    let mut cached_ephemeral = 0usize;
    for intent in &effects.ephemeral_intents {
        if intent_pipeline.record_ephemeral_intent(intent.clone())? {
            cached_ephemeral += 1;
        }
    }
    Ok(cached_ephemeral)
}

/// A fact that has been claimed from the pending queue and is ready to project.
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
        let (atomic_intents, durable_intents, ephemeral_intents) =
            partition_intents_by_execution(run.intents);
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

/// The pure result of running one projector before any SQL writes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProjectionRun {
    context: ContextSet,
    context_delta: ContextSetDelta,
    time_wakes: Vec<TimeWake>,
    intents: Vec<Intent>,
}

/// Call the protocol projector and normalize the output for the SQL pipeline.
///
/// Projection output is the complete replacement context for this fact. This
/// helper enforces that projectors only own their own context/time rows, then
/// computes the context delta that will wake dependent facts after commit.
fn run_projection_with_context(
    projector: &(impl Projector + ?Sized),
    fact: &Fact,
    previous_context: &ContextSet,
    context: ProjectionContext,
) -> Result<ProjectionRun, String> {
    let output = projector.project(fact, &context)?;
    enforce_owner_is_self(fact, &output)?;
    let context = output.context_set();
    let context_delta = diff_context_sets(previous_context, &context);
    Ok(ProjectionRun {
        context,
        context_delta,
        time_wakes: output.time_wakes,
        intents: output.intents,
    })
}

/// Reject any projected need, offer, or time wake whose `owner` is not the fact
/// being projected.
fn enforce_owner_is_self(fact: &Fact, output: &ProjectionOutput) -> Result<(), String> {
    for need in &output.needs {
        if need.owner != fact.id {
            return Err(format!(
                "projector emitted need with owner {:x?} that is not the projected fact {:x?}",
                need.owner, fact.id
            ));
        }
    }
    for offer in &output.offers {
        if offer.owner != fact.id {
            return Err(format!(
                "projector emitted offer with owner {:x?} that is not the projected fact {:x?}",
                offer.owner, fact.id
            ));
        }
    }
    for wake in &output.time_wakes {
        if wake.owner != fact.id {
            return Err(format!(
                "projector emitted time wake with owner {:x?} that is not the projected fact {:x?}",
                wake.owner, fact.id
            ));
        }
    }
    Ok(())
}

/// The committed SQL result needed to update memory and reporting.
struct ProjectionCommit {
    persisted_intents: usize,
}

/// Commit all durable and atomic projection effects in one SQLite transaction.
///
/// Transaction contents:
///
/// - Clear this fact's pending row.
/// - Replace this fact's standing context.
/// - Replace this fact's time wakes.
/// - Record the pending context change.
/// - Apply atomic row mutations.
/// - Record deferred intents.
///
/// Ephemeral intents are intentionally absent; they are cached by
/// `finish_pending_fact` only after this transaction succeeds.
fn commit_projection_effects(
    store: &Store,
    effects: &ProjectionEffects,
    allowed_tables: &[TableName],
) -> Result<ProjectionCommit, String> {
    store
        .write_transaction(|tx| {
            tx.delete_table_rows_in_tx(PENDING_PROJECTION, vec![effects.fact_id.to_vec()])?;
            delete_pending_time_ranges_for_owner_in_tx(tx, effects.fact_id)?;
            replace_stored_context_owner_rows_from_previous(
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

            Ok(ProjectionCommit { persisted_intents })
        })
        .map_err(|err| format!("commit projection effects: {err}"))
}

/// Replace this fact's standing needs/offers using the previous key set.
///
/// Projection owns the complete context set for its fact. Deleting exactly the
/// previous rows avoids wiping rows emitted by other facts with the same role.
fn replace_stored_context_owner_rows_from_previous(
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
/// Time wakes are not appended: projection output is the complete current
/// schedule for the owner, so old rows must disappear when the projection no
/// longer emits them.
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

// === Intent dispatch ===

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DispatchReport {
    pub handled: usize,
    pub facts: usize,
    pub intents: usize,
    pub retries: usize,
}

/// Restart-local state and SQL-backed dispatch for protocol intents.
///
/// Durable deferred/atomic intents live in SQLite. Ephemeral intents do not:
/// they are intentionally restart-local and are queued here. The fact cache is
/// only a dispatch convenience for ephemeral handlers; persisted facts remain
/// the source of truth.
#[derive(Debug, Default)]
pub struct IntentPipeline {
    fact_cache: BTreeMap<FactId, Fact>,
    ephemeral_intents: Vec<Intent>,
    ephemeral_intent_keys: BTreeMap<Vec<u8>, usize>,
}

impl IntentPipeline {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn submit_intent_to_store(
        &mut self,
        store: &Store,
        intent: Intent,
    ) -> Result<bool, String> {
        if intent.execution == IntentExecution::Ephemeral {
            return self.record_ephemeral_intent(intent);
        }
        let inserted = store
            .write_transaction(|tx| record_intent_in_tx(tx, &intent))
            .map_err(|err| format!("submit intent: {err}"))?;
        Ok(inserted)
    }

    pub(crate) fn ephemeral_intents(&self) -> &[Intent] {
        &self.ephemeral_intents
    }

    pub(crate) fn validate_intents(&self, intents: &[Intent]) -> Result<(), String> {
        self.validate_intents_ignoring_key(intents, None)
    }

    pub(crate) fn validate_intents_ignoring_key(
        &self,
        intents: &[Intent],
        ignored_key: Option<&[u8]>,
    ) -> Result<(), String> {
        let mut proposed = BTreeMap::<Vec<u8>, &Intent>::new();
        for intent in intents {
            let key = intent_row_key(intent);
            if !ignored_key.is_some_and(|ignored| ignored == key.as_slice()) {
                if let Some(existing_index) = self.ephemeral_intent_keys.get(&key) {
                    if self.ephemeral_intents[*existing_index] != *intent {
                        return Err(format!(
                            "intent idempotence key conflict for {}",
                            intent.kind.as_str()
                        ));
                    }
                }
            }
            if let Some(existing) = proposed.insert(key, intent) {
                if existing != intent {
                    return Err(format!(
                        "projection emitted conflicting intents for {}",
                        intent.kind.as_str()
                    ));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn record_ephemeral_intent(&mut self, intent: Intent) -> Result<bool, String> {
        let key = intent_row_key(&intent);
        if let Some(existing_index) = self.ephemeral_intent_keys.get(&key) {
            if self.ephemeral_intents[*existing_index] == intent {
                return Ok(false);
            }
            return Err(format!(
                "intent idempotence key conflict for {}",
                intent.kind.as_str()
            ));
        }
        self.ephemeral_intent_keys
            .insert(key, self.ephemeral_intents.len());
        self.ephemeral_intents.push(intent);
        Ok(true)
    }

    pub(crate) fn forget_purged_fact(&mut self, owner: FactId) {
        self.fact_cache.remove(&owner);
    }

    pub(crate) fn remember_fact(&mut self, fact: Fact) {
        self.fact_cache.entry(fact.id).or_insert(fact);
    }

    fn remove_ephemeral_intent_key(&mut self, key: &[u8]) -> Result<(), String> {
        let Some(index) = self.ephemeral_intent_keys.get(key).copied() else {
            return Ok(());
        };
        self.ephemeral_intents.remove(index);
        self.rebuild_ephemeral_intent_keys()
    }

    fn pop_next_intent_matching(
        &mut self,
        handler: &(impl IntentHandler + ?Sized),
        accepts_execution: impl Fn(&Intent) -> bool,
    ) -> Result<Option<(usize, Intent)>, String> {
        let Some(index) = self
            .ephemeral_intents
            .iter()
            .position(|intent| accepts_execution(intent) && handler.accepts(intent))
        else {
            return Ok(None);
        };
        let intent = self.ephemeral_intents.remove(index);
        self.rebuild_ephemeral_intent_keys()?;
        Ok(Some((index, intent)))
    }

    fn restore_intent(&mut self, index: usize, intent: Intent) -> Result<(), String> {
        let index = index.min(self.ephemeral_intents.len());
        self.ephemeral_intents.insert(index, intent);
        self.rebuild_ephemeral_intent_keys()
    }

    fn rebuild_ephemeral_intent_keys(&mut self) -> Result<(), String> {
        self.ephemeral_intent_keys.clear();
        for (index, intent) in self.ephemeral_intents.iter().enumerate() {
            let key = intent_row_key(intent);
            if self.ephemeral_intent_keys.insert(key, index).is_some() {
                return Err(format!(
                    "duplicate intent idempotence key for {}",
                    intent.kind.as_str()
                ));
            }
        }
        Ok(())
    }
}

/// Dispatch stored deferred intents, each with the input facts its handler asks
/// for.
pub(crate) fn dispatch_deferred_intents(
    intent_pipeline: &mut IntentPipeline,
    handler: &(impl IntentHandler + ?Sized),
    store: &Store,
    allowed_tables: &[TableName],
    limit: usize,
) -> Result<DispatchReport, String> {
    dispatch_stored_intents(
        intent_pipeline,
        handler,
        store,
        IntentExecution::Deferred,
        HandlerContextMode::InputFacts,
        allowed_tables,
        limit,
    )
}

/// Dispatch stored atomic intents.
///
/// Atomic intents are already part of the runtime's deterministic row-mutation
/// vocabulary, so handlers receive an empty fact context and the transaction
/// applies any emitted row changes alongside the handled-intent deletion.
pub(crate) fn dispatch_atomic_intents(
    intent_pipeline: &mut IntentPipeline,
    handler: &(impl IntentHandler + ?Sized),
    store: &Store,
    allowed_tables: &[TableName],
    limit: usize,
) -> Result<DispatchReport, String> {
    dispatch_stored_intents(
        intent_pipeline,
        handler,
        store,
        IntentExecution::Atomic,
        HandlerContextMode::Empty,
        allowed_tables,
        limit,
    )
}

/// Shared loop for dispatching stored (durable) intents.
///
/// Each iteration follows the prepare/commit/finish rhythm: claim one matching
/// intent, load the handler context, run the handler, then prepare, commit, and
/// finish its output. A `false` from [`finish_handler_output`] means another
/// dispatcher claimed the intent first, so the loop simply moves to the next.
fn dispatch_stored_intents(
    intent_pipeline: &mut IntentPipeline,
    handler: &(impl IntentHandler + ?Sized),
    store: &Store,
    execution: IntentExecution,
    context_mode: HandlerContextMode,
    allowed_tables: &[TableName],
    limit: usize,
) -> Result<DispatchReport, String> {
    let mut report = DispatchReport::default();
    while report.handled < limit {
        let Some(stored) = claim_stored_intent(store, handler, execution)? else {
            break;
        };
        let context = load_handler_context(store, handler, &stored.intent, context_mode)?;
        let Some(output) = run_handler(handler, &stored.intent, &context, &mut report)? else {
            break;
        };
        let output =
            prepare_handler_output(intent_pipeline, output, Some(&stored.key), allowed_tables)?;
        let commit = commit_handler_output(store, Some(&stored.key), &output, allowed_tables)?;
        if !finish_handler_output(
            intent_pipeline,
            Some(&stored.key),
            output,
            commit,
            &mut report,
        )? {
            continue;
        }
    }
    Ok(report)
}

/// Dispatch restart-local (ephemeral) intents.
///
/// Ephemeral intents were never persisted, so there is no `INTENTS` row to
/// delete and nothing on disk to fall back on after a failure. Instead the loop
/// pops one intent out of memory and restores it to its original queue position
/// if anything *before the commit* fails or asks to retry. Once the commit
/// succeeds the intent is spent, so a later `finish` error propagates as-is.
pub(crate) fn dispatch_ephemeral_intents(
    intent_pipeline: &mut IntentPipeline,
    handler: &(impl IntentHandler + ?Sized),
    store: &Store,
    allowed_tables: &[TableName],
    limit: usize,
) -> Result<DispatchReport, String> {
    let mut report = DispatchReport::default();
    while report.handled < limit {
        let Some((index, intent)) = intent_pipeline.pop_next_intent_matching(handler, |intent| {
            intent.execution == IntentExecution::Ephemeral
        })?
        else {
            break;
        };
        match run_and_commit_ephemeral_intent(
            intent_pipeline,
            handler,
            store,
            allowed_tables,
            &intent,
            &mut report,
        ) {
            Ok(EphemeralRun::Committed { output, commit }) => {
                finish_handler_output(intent_pipeline, None, output, commit, &mut report)?;
            }
            Ok(EphemeralRun::Retry) => {
                intent_pipeline.restore_intent(index, intent)?;
                break;
            }
            Err(err) => {
                intent_pipeline.restore_intent(index, intent)?;
                return Err(err);
            }
        }
    }
    Ok(report)
}

/// Outcome of [`run_and_commit_ephemeral_intent`] short of the `finish` step.
enum EphemeralRun {
    /// The handler ran and its output committed; only `finish` remains.
    Committed {
        output: HandlerOutputParts,
        commit: HandlerCommit,
    },
    /// The handler asked to be retried later; the caller should restore the
    /// intent and stop.
    Retry,
}

/// Run one popped ephemeral intent through the prepare and commit steps.
///
/// On any error the caller restores the intent, so this is free to use `?`. A
/// retryable handler error returns [`EphemeralRun::Retry`] rather than an
/// error: the intent is sound, the runtime should just try it again later.
fn run_and_commit_ephemeral_intent(
    intent_pipeline: &mut IntentPipeline,
    handler: &(impl IntentHandler + ?Sized),
    store: &Store,
    allowed_tables: &[TableName],
    intent: &Intent,
    report: &mut DispatchReport,
) -> Result<EphemeralRun, String> {
    let context = load_ephemeral_handler_context(intent_pipeline, handler, store, intent)?;
    let Some(output) = run_handler(handler, intent, &context, report)? else {
        return Ok(EphemeralRun::Retry);
    };
    let output = prepare_handler_output(intent_pipeline, output, None, allowed_tables)?;
    let commit = commit_handler_output(store, None, &output, allowed_tables)?;
    Ok(EphemeralRun::Committed { output, commit })
}

/// Build the handler context for an ephemeral intent.
///
/// Input facts come from the [`IntentPipeline`] fact cache first; anything not
/// cached is loaded from the store and remembered for next time.
fn load_ephemeral_handler_context<'a>(
    intent_pipeline: &mut IntentPipeline,
    handler: &(impl IntentHandler + ?Sized),
    store: &'a Store,
    intent: &Intent,
) -> Result<HandlerContext<'a>, String> {
    let mut context_facts = BTreeMap::new();
    for fact_id in handler.input_fact_ids(intent)? {
        let fact = match intent_pipeline.fact_cache.get(&fact_id).cloned() {
            Some(fact) => Some(fact),
            None => {
                let loaded = persisted_fact(store, &fact_id)?;
                if let Some(fact) = &loaded {
                    intent_pipeline.remember_fact(fact.clone());
                }
                loaded
            }
        };
        if let Some(fact) = fact {
            context_facts.insert(fact_id, fact);
        }
    }
    Ok(HandlerContext::with_facts(context_facts.into_values()).with_store(store))
}

/// Return the first stored intent accepted by this handler and execution mode.
fn claim_stored_intent(
    store: &Store,
    handler: &(impl IntentHandler + ?Sized),
    execution: IntentExecution,
) -> Result<Option<StoredIntent>, String> {
    for (key, value) in store
        .table_rows(INTENTS)
        .map_err(|err| format!("load stored intents: {err}"))?
    {
        let intent = decode_intent_row(&key, &value)?;
        if intent.execution == execution && handler.accepts(&intent) {
            return Ok(Some(StoredIntent { key, intent }));
        }
    }
    Ok(None)
}

/// Build the fact/store view a stored-intent handler requested.
fn load_handler_context<'a>(
    store: &'a Store,
    handler: &(impl IntentHandler + ?Sized),
    intent: &Intent,
    mode: HandlerContextMode,
) -> Result<HandlerContext<'a>, String> {
    let context = match mode {
        HandlerContextMode::Empty => HandlerContext::new(),
        HandlerContextMode::InputFacts => {
            let mut facts = Vec::new();
            for id in handler.input_fact_ids(intent)? {
                if let Some(fact) = persisted_fact(store, &id)? {
                    facts.push(fact);
                }
            }
            HandlerContext::with_facts(facts)
        }
    };
    Ok(context.with_store(store))
}

/// Run a handler and convert retry markers into report state.
fn run_handler(
    handler: &(impl IntentHandler + ?Sized),
    intent: &Intent,
    context: &HandlerContext<'_>,
    report: &mut DispatchReport,
) -> Result<Option<HandlerOutput>, String> {
    match handler.handle(intent, context) {
        Ok(output) => Ok(Some(output)),
        Err(err) => {
            if is_retryable_handler_error(&err) {
                report.retries += 1;
                Ok(None)
            } else {
                Err(err.to_string())
            }
        }
    }
}

/// Validate and split handler output before the commit transaction.
///
/// `handled_intent_key` is the durable intent being consumed, if any: its
/// idempotence key is exempt from the conflict check, since a handler is
/// allowed to re-emit the very intent it is handling. Ephemeral dispatch has no
/// such key and passes `None`.
fn prepare_handler_output(
    intent_pipeline: &IntentPipeline,
    output: HandlerOutput,
    handled_intent_key: Option<&[u8]>,
    allowed_tables: &[TableName],
) -> Result<HandlerOutputParts, String> {
    intent_pipeline.validate_intents_ignoring_key(&output.intents, handled_intent_key)?;
    validate_atomic_row_intents(&output.intents, allowed_tables)?;
    Ok(split_handler_output(output))
}

/// Commit the complete output of one handled intent in a single transaction.
///
/// This is the durable boundary for intent dispatch: purging facts, admitting
/// emitted facts, applying atomic rows, and recording deferred intents all
/// happen together. `handled_intent_key` is the durable `INTENTS` row to delete
/// in the same transaction; ephemeral dispatch passes `None`, because the intent
/// it handled only ever lived in memory. If a durable key is given but its row
/// is already gone — another dispatcher claimed it first — nothing commits and
/// the returned [`HandlerCommit::handled`] is `false`.
fn commit_handler_output(
    store: &Store,
    handled_intent_key: Option<&[u8]>,
    output: &HandlerOutputParts,
    allowed_tables: &[TableName],
) -> Result<HandlerCommit, String> {
    store
        .write_transaction(|tx| {
            if let Some(key) = handled_intent_key {
                if tx.delete_table_rows_in_tx(INTENTS, vec![key.to_vec()])? == 0 {
                    return Ok(HandlerCommit::default());
                }
            }

            for purged in &output.purged_facts {
                purge_fact_in_tx(tx, *purged)?;
            }

            let mut facts = 0usize;
            for fact in &output.facts {
                if insert_fact_and_pending_in_tx(tx, fact)? {
                    facts += 1;
                }
            }

            let (atomic_rows, atomic_deletes) =
                atomic_row_mutations(&output.atomic_intents, allowed_tables)
                    .map_err(sqlite_string_error)?;
            tx.insert_table_rows_in_tx(atomic_rows)?;
            for delete in atomic_deletes {
                tx.delete_table_rows_in_tx(delete.table, vec![delete.key])?;
            }

            let mut persisted_intents = 0usize;
            for intent in &output.durable_intents {
                if record_intent_in_tx(tx, intent)? {
                    persisted_intents += 1;
                }
            }

            Ok(HandlerCommit {
                handled: true,
                facts,
                atomic_intents: output.atomic_intents.len(),
                persisted_intents,
            })
        })
        .map_err(|err| format!("commit handler output: {err}"))
}

/// Apply the restart-local effects of a committed handler and update the report.
///
/// Runs only after [`commit_handler_output`] succeeds. `handled_intent_key` is
/// the durable key that was consumed, if any: a durable intent can have an
/// in-memory ephemeral twin sharing its idempotence key, and consuming the
/// durable copy retires the twin too. Returns whether the commit took effect —
/// `false` only when another dispatcher had already claimed the durable intent.
fn finish_handler_output(
    intent_pipeline: &mut IntentPipeline,
    handled_intent_key: Option<&[u8]>,
    output: HandlerOutputParts,
    commit: HandlerCommit,
    report: &mut DispatchReport,
) -> Result<bool, String> {
    if let Some(key) = handled_intent_key {
        intent_pipeline.remove_ephemeral_intent_key(key)?;
    }
    if !commit.handled {
        return Ok(false);
    }

    for purged in &output.purged_facts {
        intent_pipeline.forget_purged_fact(*purged);
    }
    for fact in output.facts {
        intent_pipeline.remember_fact(fact);
    }
    let mut cached_ephemeral = 0usize;
    for intent in output.ephemeral_intents {
        if intent_pipeline.record_ephemeral_intent(intent)? {
            cached_ephemeral += 1;
        }
    }

    report.handled += 1;
    report.facts += commit.facts;
    report.intents += commit.atomic_intents + commit.persisted_intents + cached_ephemeral;
    Ok(true)
}

/// Split a flat list of intents into `(atomic, deferred, ephemeral)` by their
/// execution class.
fn partition_intents_by_execution(
    intents: Vec<Intent>,
) -> (Vec<Intent>, Vec<Intent>, Vec<Intent>) {
    let mut atomic = Vec::new();
    let mut deferred = Vec::new();
    let mut ephemeral = Vec::new();
    for intent in intents {
        match intent.execution {
            IntentExecution::Atomic => atomic.push(intent),
            IntentExecution::Deferred => deferred.push(intent),
            IntentExecution::Ephemeral => ephemeral.push(intent),
        }
    }
    (atomic, deferred, ephemeral)
}

/// Split handler output by execution class once, before any commit logic.
fn split_handler_output(output: HandlerOutput) -> HandlerOutputParts {
    let (atomic_intents, durable_intents, ephemeral_intents) =
        partition_intents_by_execution(output.intents);
    HandlerOutputParts {
        facts: output.facts,
        purged_facts: output.purged_facts,
        atomic_intents,
        durable_intents,
        ephemeral_intents,
    }
}

fn is_retryable_handler_error(err: &HandlerError) -> bool {
    matches!(err, HandlerError::Retry(_))
}

#[derive(Debug, Clone, Copy)]
enum HandlerContextMode {
    Empty,
    InputFacts,
}

struct StoredIntent {
    key: Vec<u8>,
    intent: Intent,
}

/// Counts from one committed handler transaction.
#[derive(Debug, Default)]
struct HandlerCommit {
    /// Whether the transaction took effect. `false` only when a durable intent
    /// had already been claimed by another dispatcher; always `true` for
    /// ephemeral dispatch.
    handled: bool,
    facts: usize,
    atomic_intents: usize,
    persisted_intents: usize,
}

struct HandlerOutputParts {
    facts: Vec<Fact>,
    purged_facts: Vec<FactId>,
    atomic_intents: Vec<Intent>,
    durable_intents: Vec<Intent>,
    ephemeral_intents: Vec<Intent>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{ContextNeed, Role, Selector};
    use crate::core::facts::FactScope;
    use crate::core::intents::IntentKind;

    #[test]
    fn projection_run_rejects_offer_owned_by_another_fact() {
        let fact = Fact::new(FactScope::Global, 1, b"owned".to_vec());
        let projector = BadOfferOwnerProjector;

        let err = run_projection(&projector, &fact, &ContextSet::new(), Vec::new())
            .expect_err("projection should reject foreign offer owner");

        assert!(err.contains("projector emitted offer with owner"));
    }

    #[test]
    fn projection_run_rejects_need_owned_by_another_fact() {
        let fact = Fact::new(FactScope::Global, 1, b"owned".to_vec());
        let projector = BadNeedOwnerProjector;

        let err = run_projection(&projector, &fact, &ContextSet::new(), Vec::new())
            .expect_err("projection should reject foreign need owner");

        assert!(err.contains("projector emitted need with owner"));
    }

    #[test]
    fn projection_run_rejects_time_wake_owned_by_another_fact() {
        let fact = Fact::new(FactScope::Global, 1, b"owned".to_vec());
        let projector = BadTimeWakeOwnerProjector;

        let err = run_projection(&projector, &fact, &ContextSet::new(), Vec::new())
            .expect_err("projection should reject foreign time-wake owner");

        assert!(err.contains("projector emitted time wake with owner"));
    }

    #[test]
    fn projection_run_diffs_standing_context_without_self_waking() {
        let fact = Fact::new(FactScope::Global, 1, b"stable".to_vec());
        let role = Role::new("exact").unwrap();
        let selector = Selector::from_bytes([9; 32]);
        let projector = NeedUntilOffer {
            role,
            selector,
            intent_kind: IntentKind::new("followup").unwrap(),
        };

        let first =
            run_projection(&projector, &fact, &ContextSet::new(), Vec::new()).expect("first run");
        assert_eq!(first.context_delta.added_needs.len(), 1);
        assert_eq!(first.context_delta.removed_needs.len(), 0);

        let second =
            run_projection(&projector, &fact, &first.context, Vec::new()).expect("second run");
        assert!(second.context_delta.is_empty());
        assert_eq!(second.context, first.context);
        assert!(second.intents.is_empty());
    }

    #[test]
    fn projection_run_replaces_need_with_intent_when_context_appears() {
        let fact = Fact::new(FactScope::Global, 1, b"recoverable".to_vec());
        let role = Role::new("exact").unwrap();
        let selector = Selector::from_bytes([9; 32]);
        let projector = NeedUntilOffer {
            role: role.clone(),
            selector: selector.clone(),
            intent_kind: IntentKind::new("followup").unwrap(),
        };
        let previous = run_projection(&projector, &fact, &ContextSet::new(), Vec::new())
            .expect("previous projection")
            .context;
        let offer = ContextOffer {
            owner: [2; 32],
            role,
            scope: FactScope::Global,
            selector,
        };

        let next = run_projection(&projector, &fact, &previous, vec![offer])
            .expect("projection with context");

        assert!(next.context.needs.is_empty());
        assert_eq!(next.context_delta.removed_needs, previous.needs);
        assert_eq!(next.context_delta.added_needs.len(), 0);
        assert_eq!(next.intents.len(), 1);
        assert_eq!(next.intents[0].kind.as_str(), "followup");
    }

    fn run_projection(
        projector: &impl Projector,
        fact: &Fact,
        previous_context: &ContextSet,
        offers: Vec<ContextOffer>,
    ) -> Result<ProjectionRun, String> {
        run_projection_with_context(
            projector,
            fact,
            previous_context,
            ProjectionContext::new(offers),
        )
    }

    struct NeedUntilOffer {
        role: Role,
        selector: Selector,
        intent_kind: IntentKind,
    }

    impl Projector for NeedUntilOffer {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            if context.offers().is_empty() {
                Ok(ProjectionOutput::new().need(ContextNeed {
                    owner: fact.id,
                    role: self.role.clone(),
                    scope: fact.scope.clone(),
                    selector: self.selector.clone(),
                }))
            } else {
                Ok(ProjectionOutput::new().intent(Intent::new(
                    self.intent_kind.clone(),
                    IntentExecution::Atomic,
                    fact.id,
                    context.offer_owners().next().unwrap_or(fact.id),
                )))
            }
        }
    }

    struct BadOfferOwnerProjector;

    impl Projector for BadOfferOwnerProjector {
        fn project(
            &self,
            fact: &Fact,
            _context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            Ok(ProjectionOutput::new().offer(ContextOffer {
                owner: [9; 32],
                role: Role::new("exact").unwrap(),
                scope: fact.scope.clone(),
                selector: Selector::from_bytes(fact.id),
            }))
        }
    }

    struct BadNeedOwnerProjector;

    impl Projector for BadNeedOwnerProjector {
        fn project(
            &self,
            fact: &Fact,
            _context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            Ok(ProjectionOutput::new().need(ContextNeed {
                owner: [9; 32],
                role: Role::new("exact").unwrap(),
                scope: fact.scope.clone(),
                selector: Selector::from_bytes(fact.id),
            }))
        }
    }

    struct BadTimeWakeOwnerProjector;

    impl Projector for BadTimeWakeOwnerProjector {
        fn project(
            &self,
            _fact: &Fact,
            _context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            Ok(ProjectionOutput::new().time_wake(TimeWake {
                owner: [9; 32],
                timeline: Timeline::new("test").unwrap(),
                at: 1,
            }))
        }
    }
}
