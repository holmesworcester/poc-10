//! Pending fact projection step helpers.
//!
//! Core treats facts as immutable inputs and projection as the only path that
//! turns a fact into derived runtime state. Commands, handlers, sync, and local
//! submission may admit facts, but they do not update protocol tables, standing
//! context, time schedules, or follow-up work themselves. They record the fact
//! and place its id in `pending_projection`; `PipelineEngine` later drains that
//! queue and uses these helpers to run each projection step.
//!
//! This is the fact-side counterpart to intent dispatch. Dispatch consumes
//! queued intents and commits handler effects. Pending projection consumes
//! queued facts and commits projector effects. Both boundaries delay work until
//! the required inputs can be loaded, keep retries simple by leaving the input
//! row queued until success, and make output visible only in the transaction
//! that consumes the input row.
//!
//! Projection determines how every durable fact participates in the rest of the
//! runtime. A new fact enters the queue when commands, handlers, or sync admit
//! it. An existing fact re-enters when context matching discovers an offer that
//! may satisfy one of its needs, or when a due time wake gives it time-range
//! context. This is why projection is separate from both command handling and
//! intent dispatch: any source of new information can ask the same per-fact
//! projector to run again.
//!
//! This module owns the SQL-backed helper steps used by `PipelineEngine`'s
//! projection phase. It admits facts into the pending queue, turns due time
//! wakes into pending projection with time-range context, loads each pending
//! fact's previous standing context and matched inputs through
//! `pipeline::context_store`, runs the protocol projector, and commits the
//! replacement context plus projector `PipelineEffects` in one transaction. The
//! shared effects are written by `commit_effects`; this file owns the
//! projection-specific SQL and projector mechanics around them.
//!
//! Projection is intentionally per fact. Everything before
//! `commit_projection_effects` is calculation; that function is the single
//! durable boundary that clears the pending row, replaces the fact's context
//! and time wakes, wakes newly matched dependent facts, and commits the
//! projector's shared effects. Queue order and batching policy belong in
//! `PipelineEngine`; SQL mechanics for one projection step belong here.

use super::commit_effects::{
    commit_pipeline_effects_in_tx, sqlite_string_error, suppress_disallowed_intents,
    validate_pipeline_effects_for_admission, IntentAdmissionPolicy,
};
use super::context_store::{
    insert_context_need_in_tx, insert_context_offer_in_tx, stored_context_for_owner,
    stored_matching_context, wake_context_matches_in_tx,
};
use super::insert_select;
use super::route::FactAdmissionFn;
use crate::core::context::{diff_context_sets, ContextOffer, ContextSet, ContextSetDelta};
use crate::core::effects::PipelineEffects;
use crate::core::fact_store::{
    delete_ephemeral_fact_in_tx, ephemeral_fact_by_id, ephemeral_pending_fact_ids,
    insert_fact_and_pending_in_tx, persisted_fact, purge_fact_in_tx,
};
use crate::core::facts::{Fact, FactId};
use crate::core::pipeline::{
    ProjectionContext, ProjectionOutput, Projector, TimeRange, TimeWake, Timeline,
};
use crate::core::schema::{PENDING_PROJECTION, PENDING_TIME_RANGES, TIME_WAKES};
use crate::core::store::{Store, TableName};
use rusqlite::params;

const TIME_WAKE_TABLES: &[TableName] = &[TIME_WAKES];
const PROJECTION_CONTEXT_FIXPOINT_LIMIT: usize = 8;
pub(super) const DURABLE_PROJECTION_TRANSACTION_CHUNK_LIMIT: usize = 256;

const DUE_TIME_WAKE_OWNER_SQL: &str = r#"
SELECT owner
FROM time_wakes
WHERE timeline = :timeline
  AND (:has_start = 0 OR at > :start_exclusive)
  AND at <= :end_inclusive
ORDER BY at, owner
LIMIT :limit
"#;

const DUE_TIME_RANGE_SQL: &str = r#"
SELECT owner,
       :timeline AS timeline,
       :has_start AS has_start,
       :start_exclusive AS start_exclusive,
       :end_inclusive AS end_inclusive
FROM time_wakes
WHERE timeline = :timeline
  AND (:has_start = 0 OR at > :start_exclusive)
  AND at <= :end_inclusive
ORDER BY at, owner
LIMIT :limit
"#;

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
) -> Result<usize, String> {
    store
        .write_transaction(|tx| {
            let mut added_offers = Vec::new();
            for offer in offers {
                if insert_context_offer_in_tx(tx, offer)? {
                    added_offers.push(offer.clone());
                }
            }
            let woken_facts = wake_context_matches_in_tx(
                tx,
                &ContextSetDelta {
                    added_offers,
                    ..ContextSetDelta::default()
                },
            )
            .map_err(sqlite_string_error)?;
            for id in completed_fact_ids {
                tx.conn().execute(
                    "DELETE FROM pending_projection WHERE owner = ?1",
                    params![id.as_slice()],
                )?;
            }
            Ok(woken_facts)
        })
        .map_err(|err| format!("commit projected context offers: {err}"))
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

    store
        .write_transaction(|tx| enqueue_due_time_wakes_in_tx(tx, &range, limit))
        .map_err(|err| format!("process due time range: {err}"))
}

fn enqueue_due_time_wakes_in_tx(
    store: &Store,
    range: &TimeRange,
    limit: usize,
) -> rusqlite::Result<usize> {
    let has_start = range.start_exclusive.is_some();
    let start_exclusive = range.start_exclusive.unwrap_or(0);
    let params = vec![
        insert_select::Param::text(":timeline", range.timeline.as_str()),
        insert_select::Param::bool(":has_start", has_start),
        insert_select::Param::u64(":start_exclusive", start_exclusive),
        insert_select::Param::u64(":end_inclusive", range.end_inclusive),
        insert_select::Param::u64(":limit", limit as u64),
    ];

    let inserted = insert_select::insert_select_in_tx(
        store,
        PENDING_PROJECTION,
        &["owner"],
        &insert_select::Select::new(DUE_TIME_WAKE_OWNER_SQL, TIME_WAKE_TABLES, params.clone()),
    )?;

    insert_select::insert_select_in_tx(
        store,
        PENDING_TIME_RANGES,
        &[
            "owner",
            "timeline",
            "has_start",
            "start_exclusive",
            "end_inclusive",
        ],
        &insert_select::Select::new(DUE_TIME_RANGE_SQL, TIME_WAKE_TABLES, params),
    )?;

    Ok(inserted)
}

/// Isolate a durable fact whose projection or authentication was rejected.
///
/// The batch-safety fix: a single rejected fact must not abort projection of the
/// rest of the chunk. We then classify the rejection by re-projecting the fact
/// over an *empty* context — a side-effect-free probe that separates the two
/// kinds of failure, because the projector runs the authenticator first:
///
/// - **Fails without context** (re-project errors): the failure is context-free
///   — a bad signature, id, intrinsic field, or scope. The bytes are not
///   admissible protocol data, so purge the fact, the same way beyond-ceiling
///   bytes are dropped.
/// - **Otherwise** (re-project succeeds — it just parks on a need): the fact
///   authenticates and is well-formed; the original rejection came from
///   *inconsistent context*. Keep the fact and remove only its
///   pending-projection marker so the drain does not retry it. Such a fact is
///   kept as evidence: versioning needs different lenses and versions to
///   interpret an incorrect fact the same way, and purging would destroy the
///   test subject.
pub(super) fn isolate_rejected_durable_fact_in_tx(
    tx: &Store,
    fact_id: FactId,
    projector: &(impl Projector + ?Sized),
) -> rusqlite::Result<()> {
    if durable_fact_fails_without_context(tx, fact_id, projector) {
        purge_fact_in_tx(tx, fact_id)?;
        return Ok(());
    }
    tx.conn().execute(
        "DELETE FROM pending_projection WHERE owner = ?1",
        params![fact_id.as_slice()],
    )?;
    Ok(())
}

/// Probe whether a durable fact fails projection for context-free reasons.
///
/// Re-projects the fact against an empty context. The projector authenticates
/// first (signature, id, intrinsic fields) and then checks scope before any
/// context lookup, so a context-free failure (inauthentic or structurally
/// malformed) errors here, while a fact that only depends on missing context
/// parks on a need and returns `Ok`. Pure: projection has no side effects.
fn durable_fact_fails_without_context(
    tx: &Store,
    fact_id: FactId,
    projector: &(impl Projector + ?Sized),
) -> bool {
    match persisted_fact(tx, &fact_id) {
        Ok(Some(fact)) => projector
            .project(&fact, &ProjectionContext::default())
            .is_err(),
        // Already gone, or unreadable: nothing to purge — just clear the marker.
        _ => false,
    }
}

/// Run the protocol projector for one fact and split its output.
///
/// No rows are written here. The result is an uncommitted `ProjectionEffects`
/// value that says what should happen if the projection commits.
///
/// This preparation step deliberately runs a small monotonic fixed point before
/// the transaction. Projectors own the decision about whether context is
/// required, optional, or just a wake trigger, so core does not interpret any
/// need. It only asks: "given the needs this run emitted, are there already
/// stored offers that should be visible to this same projection?" If yes, core
/// adds those matches to the in-memory projection context and reruns before any
/// rows, intents, or replacement context are committed. Only the final run below
/// becomes durable.
pub(super) fn prepare_projection_effects(
    projector: &(impl Projector + ?Sized),
    pending_fact: PendingFact,
    store: &Store,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    intent_policy: IntentAdmissionPolicy<'_>,
) -> Result<ProjectionEffects, String> {
    let PendingFact {
        source,
        fact_id,
        fact,
        previous_context,
        mut projection_context,
    } = pending_fact;
    let run = run_projection_to_context_fixed_point(
        projector,
        &fact,
        &previous_context,
        &mut projection_context,
        store,
        allowed_tables,
        fact_admission,
        intent_policy,
    )?;
    let mut pipeline = run.pipeline;
    let suppressed_intents = suppress_disallowed_intents(&mut pipeline, intent_policy);
    Ok(ProjectionEffects {
        source,
        fact_id,
        next_context: run.context,
        next_time_wakes: run.time_wakes,
        context_delta: run.context_delta,
        pipeline,
        suppressed_intents,
    })
}

fn run_projection_to_context_fixed_point(
    projector: &(impl Projector + ?Sized),
    fact: &Fact,
    previous_context: &ContextSet,
    projection_context: &mut ProjectionContext,
    store: &Store,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    intent_policy: IntentAdmissionPolicy<'_>,
) -> Result<ProjectionRun, String> {
    for _ in 0..PROJECTION_CONTEXT_FIXPOINT_LIMIT {
        let run = crate::core::perf_profile::measure_result("projection_projector_cpu", || {
            run_projection_with_context(
                projector,
                fact,
                previous_context,
                projection_context.clone(),
            )
        })?;
        crate::core::perf_profile::measure_result("projection_validate_effects", || {
            let mut validation_pipeline = run.pipeline.clone();
            suppress_disallowed_intents(&mut validation_pipeline, intent_policy);
            validate_pipeline_effects_for_admission(
                &validation_pipeline,
                allowed_tables,
                fact_admission,
            )
        })?;

        let matched_context = crate::core::perf_profile::measure_result(
            "projection_fixedpoint_context_match",
            || stored_matching_context(store, &run.context),
        )?;
        if !projection_context.extend_with_matches(matched_context) {
            return Ok(run);
        }
    }

    Err(format!(
        "projection context for fact {:x?} did not settle after {PROJECTION_CONTEXT_FIXPOINT_LIMIT} runs",
        fact.id
    ))
}

/// The uncommitted output of projecting one pending fact.
pub(super) struct ProjectionEffects {
    source: ProjectionSource,
    fact_id: FactId,
    next_context: ContextSet,
    next_time_wakes: Vec<TimeWake>,
    context_delta: ContextSetDelta,
    pipeline: PipelineEffects,
    suppressed_intents: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ProjectionSource {
    Durable,
    Ephemeral,
}

/// Commit one pending fact's complete projection result.
///
/// This is the projection boundary, the same way `commit_handler_output` is the
/// dispatch boundary. The transaction consumes this fact's pending row and makes
/// the projector's output visible: replacement context, replacement time wakes,
/// newly woken dependent facts, protocol row mutations, and follow-up intents.
/// If projection fails before this function, the pending row remains queued. If
/// anything fails inside this transaction, SQLite rolls the whole boundary back.
///
/// Projector-emitted child facts are admitted and projected immediately inside
/// this same transaction before residual row mutations and intents are written.
/// That gives a projector one atomic decision: either the child can be stored,
/// parked on durable context, or the whole projection fails and remains queued.
///
/// Transaction contents:
///
/// - Clear this fact's pending row.
/// - Replace this fact's standing context.
/// - Replace this fact's time wakes.
/// - Wake context matches directly.
/// - Apply row mutations.
/// - Record durable intents.
/// - Record ephemeral intents in the temp local queue.
///
/// Ephemeral inputs are one-shot. They may emit needs as transient probes so
/// the projection fixed point can attach context that is already available, but
/// they cannot leave standing offers or time wakes behind after the projection
/// commits.
pub(super) fn commit_projection_effects(
    store: &Store,
    effects: &ProjectionEffects,
    projector: &(impl Projector + ?Sized),
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    intent_policy: IntentAdmissionPolicy<'_>,
) -> Result<usize, String> {
    store
        .write_transaction(|tx| {
            let suppressed_intents =
                crate::core::perf_profile::measure_result("projection_commit_tx_body", || {
                    commit_projection_effects_in_tx(
                        tx,
                        effects,
                        projector,
                        allowed_tables,
                        fact_admission,
                        intent_policy,
                        0,
                    )
                })?;
            Ok(suppressed_intents)
        })
        .map_err(|err| format!("commit projection effects: {err}"))
}

const CHILD_PROJECTION_DEPTH_LIMIT: usize = 16;

pub(super) fn commit_projection_effects_in_tx(
    tx: &Store,
    effects: &ProjectionEffects,
    projector: &(impl Projector + ?Sized),
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    intent_policy: IntentAdmissionPolicy<'_>,
    depth: usize,
) -> rusqlite::Result<usize> {
    match effects.source {
        ProjectionSource::Durable => {
            crate::core::perf_profile::measure_result("projection_clear_pending", || {
                tx.conn().execute(
                    "DELETE FROM pending_projection WHERE owner = ?1",
                    params![effects.fact_id.as_slice()],
                )
            })?;
            crate::core::perf_profile::measure_result(
                "projection_delete_pending_time_ranges",
                || delete_pending_time_ranges_for_owner_in_tx(tx, effects.fact_id),
            )?;
            crate::core::perf_profile::measure_result("projection_replace_context", || {
                replace_stored_context_owner_rows(tx, effects.fact_id, &effects.next_context)
            })?;
            crate::core::perf_profile::measure_result("projection_replace_time_wakes", || {
                replace_stored_time_wake_owner_rows(tx, effects.fact_id, &effects.next_time_wakes)
            })?;
            crate::core::perf_profile::measure_result("projection_wake_context_matches", || {
                wake_context_matches_in_tx(tx, &effects.context_delta).map_err(sqlite_string_error)
            })?;
        }
        ProjectionSource::Ephemeral => {
            validate_ephemeral_projection(effects).map_err(sqlite_string_error)?;
            crate::core::perf_profile::measure_result("projection_replace_context", || {
                replace_stored_context_owner_rows(tx, effects.fact_id, &ContextSet::new())
            })?;
            crate::core::perf_profile::measure_result("projection_delete_ephemeral_fact", || {
                delete_ephemeral_fact_in_tx(tx, effects.fact_id)
            })?;
        }
    }

    let child_suppressed =
        crate::core::perf_profile::measure_result("projection_commit_pipeline_effects", || {
            commit_projector_pipeline_effects_in_tx(
                tx,
                projector,
                allowed_tables,
                fact_admission,
                &effects.pipeline,
                intent_policy,
                depth,
            )
        })?;
    Ok(effects.suppressed_intents + child_suppressed)
}

fn validate_ephemeral_projection(effects: &ProjectionEffects) -> Result<(), String> {
    if !effects.next_context.offers.is_empty() {
        return Err("ephemeral projection input cannot emit durable offers".to_string());
    }
    if !effects.next_time_wakes.is_empty() {
        return Err("ephemeral projection input cannot emit time wakes".to_string());
    }
    if !effects.next_context.needs.is_empty() && !pipeline_effects_are_empty(&effects.pipeline) {
        return Err(
            "ephemeral projection input cannot emit effects while transient needs remain"
                .to_string(),
        );
    }
    Ok(())
}

fn pipeline_effects_are_empty(effects: &PipelineEffects) -> bool {
    effects.facts.is_empty()
        && effects.ephemeral_facts.is_empty()
        && effects.purged_facts.is_empty()
        && effects.row_mutations.is_empty()
        && effects.intents.is_empty()
        && effects.local_intents.is_empty()
}

fn commit_projector_pipeline_effects_in_tx(
    tx: &Store,
    projector: &(impl Projector + ?Sized),
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    pipeline: &PipelineEffects,
    intent_policy: IntentAdmissionPolicy<'_>,
    depth: usize,
) -> rusqlite::Result<usize> {
    if depth >= CHILD_PROJECTION_DEPTH_LIMIT {
        return Err(sqlite_string_error(format!(
            "child fact projection exceeded depth limit {CHILD_PROJECTION_DEPTH_LIMIT}"
        )));
    }

    let mut suppressed_intents = 0usize;
    for fact in &pipeline.facts {
        suppressed_intents += project_child_fact_in_tx(
            tx,
            projector,
            allowed_tables,
            fact_admission,
            fact,
            intent_policy,
            depth + 1,
        )?;
    }

    let mut residual = pipeline.clone();
    residual.facts.clear();
    commit_pipeline_effects_in_tx(tx, &residual, allowed_tables, fact_admission)?;
    Ok(suppressed_intents)
}

fn project_child_fact_in_tx(
    tx: &Store,
    projector: &(impl Projector + ?Sized),
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    fact: &Fact,
    intent_policy: IntentAdmissionPolicy<'_>,
    depth: usize,
) -> rusqlite::Result<usize> {
    if let Some(admit) = fact_admission {
        admit(fact).map_err(sqlite_string_error)?;
    }
    if !insert_fact_and_pending_in_tx(tx, fact)? {
        return Ok(0);
    }
    let pending = load_pending_fact(tx, ProjectionSource::Durable, fact.id)
        .map_err(sqlite_string_error)?
        .ok_or_else(|| sqlite_string_error("inserted child fact did not load".to_string()))?;
    let effects = prepare_projection_effects(
        projector,
        pending,
        tx,
        allowed_tables,
        fact_admission,
        intent_policy,
    )
    .map_err(sqlite_string_error)?;
    commit_projection_effects_in_tx(
        tx,
        &effects,
        projector,
        allowed_tables,
        fact_admission,
        intent_policy,
        depth,
    )
}

/// Clear due time ranges after the owner consumes them.
///
/// Time ranges are transient projection context, not standing schedule. The
/// schedule lives in `time_wakes` and is replaced by each successful projection.
fn delete_pending_time_ranges_for_owner_in_tx(
    store: &Store,
    owner: FactId,
) -> rusqlite::Result<usize> {
    store.conn().execute(
        "DELETE FROM pending_time_ranges WHERE owner = ?1",
        params![owner.as_slice()],
    )
}

/// Replace this fact's standing needs/offers by owner.
///
/// Projection owns the complete context set for its fact. The owner column is
/// the fact id, so deleting by owner replaces exactly this fact's rows.
fn replace_stored_context_owner_rows(
    store: &Store,
    owner: FactId,
    context: &ContextSet,
) -> rusqlite::Result<()> {
    store.conn().execute(
        "DELETE FROM context_edges WHERE owner = ?1",
        params![owner.as_slice()],
    )?;
    for need in &context.needs {
        insert_context_need_in_tx(store, need)?;
    }
    for offer in &context.offers {
        insert_context_offer_in_tx(store, offer)?;
    }
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
    store.conn().execute(
        "DELETE FROM time_wakes WHERE owner = ?1",
        params![owner.as_slice()],
    )?;
    for wake in wakes {
        store.conn().execute(
            "INSERT OR IGNORE INTO time_wakes (timeline, at, owner)
             VALUES (?1, ?2, ?3)",
            params![
                wake.timeline.as_str(),
                sqlite_u64(wake.at, "time wake")?,
                wake.owner.as_slice()
            ],
        )?;
    }
    Ok(())
}

fn sqlite_u64(value: u64, name: &str) -> rusqlite::Result<i64> {
    i64::try_from(value).map_err(|_| {
        rusqlite::Error::InvalidParameterName(format!("{name} exceeds SQLite integer range"))
    })
}

/// A fact that has been claimed from the pending queue and is ready to project.
pub(super) struct PendingFact {
    source: ProjectionSource,
    fact_id: FactId,
    fact: Fact,
    previous_context: ContextSet,
    projection_context: ProjectionContext,
}

impl PendingFact {
    pub(super) fn fact_id(&self) -> FactId {
        self.fact_id
    }
}

/// Read the next pending fact ids without mutating the queue.
///
/// The commit step removes the row only after projection succeeds. Missing
/// facts are handled by the caller as stale pending rows and purged there.
pub(super) fn pending_owner_batch(store: &Store, limit: usize) -> Result<Vec<FactId>, String> {
    let limit =
        i64::try_from(limit).map_err(|_| "pending projection limit exceeds i64".to_string())?;
    let mut stmt = store
        .conn()
        .prepare(
            r#"
            SELECT p.owner
            FROM pending_projection p
            LEFT JOIN local_fact_admissions m ON m.fact_id = p.owner
            ORDER BY COALESCE(m.received_at, 9223372036854775807), p.owner
            LIMIT ?1
            "#,
        )
        .map_err(|err| format!("load pending projection: {err}"))?;
    let rows = stmt
        .query_map(params![limit], |row| {
            fact_id_column(row.get::<_, Vec<u8>>(0)?, "owner")
        })
        .map_err(|err| format!("load pending projection: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("load pending projection: {err}"))
}

/// Load everything projection needs for one fact.
///
/// `previous_context` is the fact's standing context before this run.
/// `projection_context` is the matched input context exposed to the projector
/// for this run, including any due time ranges.
pub(super) fn pending_ephemeral_batch(store: &Store, limit: usize) -> Result<Vec<FactId>, String> {
    ephemeral_pending_fact_ids(store, limit)
}

pub(super) fn drop_stale_ephemeral_input(store: &Store, fact_id: FactId) -> Result<(), String> {
    store
        .write_transaction(|tx| delete_ephemeral_fact_in_tx(tx, fact_id))
        .map_err(|err| format!("purge stale ephemeral projection input: {err}"))?;
    Ok(())
}

pub(super) fn drop_rejected_ephemeral_input(store: &Store, fact_id: FactId) -> Result<(), String> {
    store
        .write_transaction(|tx| delete_ephemeral_fact_in_tx(tx, fact_id))
        .map_err(|err| format!("drop rejected ephemeral projection input: {err}"))?;
    Ok(())
}

pub(super) fn purge_stale_durable_pending_in_tx(
    tx: &Store,
    fact_id: FactId,
) -> rusqlite::Result<bool> {
    purge_fact_in_tx(tx, fact_id)
}

pub(super) fn load_pending_fact(
    store: &Store,
    source: ProjectionSource,
    fact_id: FactId,
) -> Result<Option<PendingFact>, String> {
    let fact =
        crate::core::perf_profile::measure_result("projection_load_fact", || match source {
            ProjectionSource::Durable => persisted_fact(store, &fact_id),
            ProjectionSource::Ephemeral => ephemeral_fact_by_id(store, &fact_id),
        })?;
    let Some(fact) = fact else {
        return Ok(None);
    };
    let previous_context =
        crate::core::perf_profile::measure_result("projection_load_previous_context", || {
            stored_context_for_owner(store, &fact_id)
        })?;
    let projection_context = match source {
        ProjectionSource::Durable => {
            let time_ranges = crate::core::perf_profile::measure_result(
                "projection_load_pending_time_ranges",
                || pending_time_ranges_for_owner(store, &fact_id),
            )?;
            crate::core::perf_profile::measure_result("projection_initial_context_match", || {
                stored_matching_context(store, &previous_context)
            })?
            .with_time_ranges(time_ranges)
        }
        ProjectionSource::Ephemeral => {
            crate::core::perf_profile::measure_result("projection_initial_context_match", || {
                stored_matching_context(store, &previous_context)
            })?
        }
    };
    Ok(Some(PendingFact {
        source,
        fact_id,
        fact,
        previous_context,
        projection_context,
    }))
}

fn pending_time_ranges_for_owner(store: &Store, owner: &FactId) -> Result<Vec<TimeRange>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            r#"
            SELECT timeline, has_start, start_exclusive, end_inclusive
            FROM pending_time_ranges
            WHERE owner = ?1
            ORDER BY timeline, has_start, start_exclusive, end_inclusive
            "#,
        )
        .map_err(|err| format!("load pending time ranges: {err}"))?;
    let rows = stmt
        .query_map(params![owner.as_slice()], decode_pending_time_range)
        .map_err(|err| format!("load pending time ranges: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("load pending time ranges: {err}"))
}

/// Decode one due time range row stored by `enqueue_due_time_wakes_in_tx`.
fn decode_pending_time_range(row: &rusqlite::Row<'_>) -> rusqlite::Result<TimeRange> {
    let timeline =
        Timeline::new(row.get::<_, String>(0)?).map_err(rusqlite::Error::InvalidParameterName)?;
    let has_start = match row.get::<_, i64>(1)? {
        0 => false,
        1 => true,
        other => {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "pending time range has invalid bool {other}"
            )));
        }
    };
    let start = u64_column(row.get::<_, i64>(2)?, "start_exclusive")?;
    let end_inclusive = u64_column(row.get::<_, i64>(3)?, "end_inclusive")?;
    Ok(TimeRange {
        timeline,
        start_exclusive: has_start.then_some(start),
        end_inclusive,
    })
}

fn fact_id_column(bytes: Vec<u8>, name: &str) -> rusqlite::Result<FactId> {
    bytes.try_into().map_err(|_| {
        rusqlite::Error::InvalidParameterName(format!("{name} is not a 32-byte fact id"))
    })
}

fn u64_column(value: i64, name: &str) -> rusqlite::Result<u64> {
    u64::try_from(value)
        .map_err(|_| rusqlite::Error::InvalidParameterName(format!("{name} is negative")))
}

/// The pure result of running one projector before any SQL writes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProjectionRun {
    context: ContextSet,
    context_delta: ContextSetDelta,
    time_wakes: Vec<TimeWake>,
    pipeline: PipelineEffects,
}

/// Call the protocol projector and normalize the output for the SQL pipeline.
///
/// Projection output is the complete replacement context for this fact. This
/// helper enforces that projectors only own their own context/time rows and may
/// purge only their own fact, then computes the context delta that will wake
/// dependent facts after commit.
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
        pipeline: output.effects,
    })
}

/// Reject any projected need, offer, time wake, or purge whose owner is not the
/// fact being projected.
fn enforce_owner_is_self(fact: &Fact, output: &ProjectionOutput) -> Result<(), String> {
    for purged in &output.effects.purged_facts {
        if *purged != fact.id {
            return Err(format!(
                "projector tried to purge fact {:x?} while projecting {:x?}",
                purged, fact.id
            ));
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{ContextKey, ContextNeed, ContextOffer, Role};
    use crate::core::facts::{FactId, FactScope};
    use crate::core::intents::{Intent, IntentKind};

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

        assert!(err.contains("projector emitted time wake"));
    }

    #[test]
    fn projection_run_rejects_purge_owned_by_another_fact() {
        let fact = Fact::new(FactScope::Global, 1, b"owned".to_vec());
        let projector = BadPurgeOwnerProjector;

        let err = run_projection(&projector, &fact, &ContextSet::new(), Vec::new())
            .expect_err("projection should reject foreign purge owner");

        assert!(err.contains("projector tried to purge fact"));
    }

    #[test]
    fn projection_run_allows_self_purge() {
        let fact = Fact::new(FactScope::Global, 1, b"owned".to_vec());
        let projector = SelfPurgeProjector;

        let run = run_projection(&projector, &fact, &ContextSet::new(), Vec::new())
            .expect("projection should allow self purge");

        assert_eq!(run.pipeline.purged_facts, vec![fact.id]);
    }

    #[test]
    fn projection_run_diffs_standing_context_without_self_waking() {
        let fact = Fact::new(FactScope::Global, 1, b"stable".to_vec());
        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([9; 32]);
        let projector = NeedUntilOffer {
            role,
            key,
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
        assert!(second.pipeline.intents.is_empty());
    }

    #[test]
    fn projection_run_replaces_need_with_intent_when_context_appears() {
        let fact = Fact::new(FactScope::Global, 1, b"recoverable".to_vec());
        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([9; 32]);
        let projector = NeedUntilOffer {
            role: role.clone(),
            key: key.clone(),
            intent_kind: IntentKind::new("followup").unwrap(),
        };
        let previous = run_projection(&projector, &fact, &ContextSet::new(), Vec::new())
            .expect("previous projection")
            .context;
        let offer = ContextOffer {
            owner: [2; 32],
            role,
            scope: FactScope::Global,
            start_key: key.clone(),
            end_key: key,
        };

        let next = run_projection(&projector, &fact, &previous, vec![offer])
            .expect("projection with context");

        assert!(next.context.needs.is_empty());
        assert_eq!(next.context_delta.removed_needs, previous.needs);
        assert_eq!(next.context_delta.added_needs.len(), 0);
        assert_eq!(next.pipeline.intents.len(), 1);
        assert_eq!(next.pipeline.intents[0].kind.as_str(), "followup");
    }

    #[test]
    fn prepare_projection_reruns_on_existing_matches_before_commit() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let target = Fact::new(FactScope::Global, 1, b"target".to_vec());
        let offered = Fact::new(FactScope::Global, 2, b"available".to_vec());
        submit_fact_to_store(&store, offered.clone()).expect("persist offer payload");

        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([7; 32]);
        let offer = ContextOffer {
            owner: offered.id,
            role: role.clone(),
            scope: target.scope.clone(),
            start_key: key.clone(),
            end_key: key.clone(),
        };
        crate::core::pipeline::context_store::insert_context_offer_for_test(&store, &offer)
            .expect("insert stored offer");

        let projector = PrematureNeedUntilPayload {
            role: role.clone(),
            key: key.clone(),
        };
        let pending = PendingFact {
            source: ProjectionSource::Durable,
            fact_id: target.id,
            fact: target,
            previous_context: ContextSet::new(),
            projection_context: ProjectionContext::default(),
        };
        let effects = prepare_projection_effects(
            &projector,
            pending,
            &store,
            &[],
            None,
            IntentAdmissionPolicy::All,
        )
        .expect("prepare projection");

        assert!(effects.next_context.needs.is_empty());
        assert!(effects.context_delta.is_empty());
        assert_eq!(effects.pipeline.intents.len(), 1);
        assert_eq!(effects.pipeline.intents[0].kind.as_str(), "ready");
        assert_eq!(effects.pipeline.intents[0].payload, offered.id.to_vec());
    }

    #[test]
    fn prepare_projection_reruns_through_range_match() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let target = Fact::new(FactScope::Global, 1, b"target".to_vec());
        let offered = Fact::new(FactScope::Global, 2, b"custom".to_vec());
        submit_fact_to_store(&store, offered.clone()).expect("persist offer payload");

        let role = Role::new("range").unwrap();
        let key = ContextKey::from_bytes(b"m");
        let offer = ContextOffer {
            owner: offered.id,
            role: role.clone(),
            scope: target.scope.clone(),
            start_key: ContextKey::from_bytes(b"a"),
            end_key: ContextKey::from_bytes(b"z"),
        };
        crate::core::pipeline::context_store::insert_context_offer_for_test(&store, &offer)
            .expect("insert stored offer");

        let pending = PendingFact {
            source: ProjectionSource::Durable,
            fact_id: target.id,
            fact: target,
            previous_context: ContextSet::new(),
            projection_context: ProjectionContext::default(),
        };
        let projector = PrematureNeedUntilPayload {
            role: role.clone(),
            key,
        };
        let effects = prepare_projection_effects(
            &projector,
            pending,
            &store,
            &[],
            None,
            IntentAdmissionPolicy::All,
        )
        .expect("prepare projection");

        assert!(effects.next_context.needs.is_empty());
        assert_eq!(effects.pipeline.intents.len(), 1);
        assert_eq!(effects.pipeline.intents[0].kind.as_str(), "ready");
        assert_eq!(effects.pipeline.intents[0].payload, offered.id.to_vec());
    }

    #[test]
    fn durable_batch_projection_reads_context_written_by_earlier_pending_fact() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let offered = Fact::new(FactScope::Global, 1, b"batch-offer".to_vec());
        let dependent = Fact::new(FactScope::Global, 2, b"batch-dependent".to_vec());
        assert_eq!(
            submit_facts_to_store(&store, vec![offered.clone(), dependent.clone()])
                .expect("submit pending facts"),
            2
        );

        let role = Role::new("same_batch_dep").unwrap();
        let key = ContextKey::from_bytes(b"shared-key");
        let progress = drain_pending_projection(
            &SameBatchDependencyProjector {
                offered_id: offered.id,
                dependent_id: dependent.id,
                role: role.clone(),
                key: key.clone(),
            },
            &store,
            &[],
            None,
            2,
        )
        .expect("drain same-batch dependency");

        assert_eq!(progress.projected, 2);
        let payload = intent_payload_for(&store, "same_batch_ready", &dependent.id);
        assert_eq!(payload, offered.id.to_vec());
        let dependent_context =
            stored_context_for_owner(&store, &dependent.id).expect("dependent context");
        assert!(dependent_context.needs.is_empty());
        assert_eq!(pending_projection_count(&store, offered.id), 0);
        assert_eq!(pending_projection_count(&store, dependent.id), 0);
    }

    #[test]
    fn durable_batch_isolates_a_failed_fact_without_rolling_back_the_batch() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let offered = Fact::new(FactScope::Global, 1, b"rollback-batch-offer".to_vec());
        let failing = Fact::new(FactScope::Global, 2, b"rollback-batch-fail".to_vec());
        assert_eq!(
            submit_facts_to_store(&store, vec![offered.clone(), failing.clone()])
                .expect("submit pending facts"),
            2
        );

        // One fact failing projection no longer aborts the batch: it is isolated
        // and the rest commit.
        let progress = drain_pending_projection(
            &RollbackBatchProjector {
                offered_id: offered.id,
                failing_id: failing.id,
                role: Role::new("rollback_dep").unwrap(),
                key: ContextKey::from_bytes(b"rollback-key"),
            },
            &store,
            &[],
            None,
            2,
        )
        .expect("a failed fact must not abort the batch");

        // The healthy fact committed — its neighbor's failure did not roll it back.
        assert_eq!(progress.projected, 1);
        assert_eq!(pending_projection_count(&store, offered.id), 0);
        assert!(context_edge_count(&store, offered.id) > 0);

        // The failing fact fails regardless of context (context-free), so it is
        // purged: not retried and its bytes dropped.
        assert_eq!(pending_projection_count(&store, failing.id), 0);
        assert!(crate::core::fact_store::persisted_fact(&store, &failing.id)
            .expect("load failing fact")
            .is_none());
    }

    #[test]
    fn durable_batch_keeps_a_context_inconsistent_fact_as_evidence() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let offered = Fact::new(FactScope::Global, 1, b"inconsistent-offer".to_vec());
        let failing = Fact::new(FactScope::Global, 2, b"inconsistent-dependent".to_vec());
        assert_eq!(
            submit_facts_to_store(&store, vec![offered.clone(), failing.clone()])
                .expect("submit pending facts"),
            2
        );

        let progress = drain_pending_projection(
            &ContextInconsistentProjector {
                offered_id: offered.id,
                failing_id: failing.id,
                role: Role::new("inconsistent_dep").unwrap(),
                key: ContextKey::from_bytes(b"inconsistent-key"),
            },
            &store,
            &[],
            None,
            2,
        )
        .expect("a context-inconsistent fact must not abort the batch");

        assert_eq!(progress.projected, 1);
        assert_eq!(pending_projection_count(&store, offered.id), 0);

        // The failing fact authenticates (it parks when probed with empty
        // context), so the rejection was inconsistent *context*: it is kept as
        // evidence (bytes retained) and just not retried (pending cleared).
        assert_eq!(pending_projection_count(&store, failing.id), 0);
        assert!(crate::core::fact_store::persisted_fact(&store, &failing.id)
            .expect("load failing fact")
            .is_some());
    }

    #[test]
    fn prepare_projection_leaves_watch_need_in_projector_output() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let target = Fact::new(FactScope::Global, 1, b"watcher".to_vec());
        let offered = Fact::new(FactScope::Global, 2, b"watched".to_vec());
        submit_fact_to_store(&store, offered.clone()).expect("persist offer payload");

        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([8; 32]);
        let offer = ContextOffer {
            owner: offered.id,
            role: role.clone(),
            scope: target.scope.clone(),
            start_key: key.clone(),
            end_key: key.clone(),
        };
        crate::core::pipeline::context_store::insert_context_offer_for_test(&store, &offer)
            .expect("insert stored offer");

        let pending = PendingFact {
            source: ProjectionSource::Durable,
            fact_id: target.id,
            fact: target,
            previous_context: ContextSet::new(),
            projection_context: ProjectionContext::default(),
        };
        let effects = prepare_projection_effects(
            &WatchNeedProjector { role, key },
            pending,
            &store,
            &[],
            None,
            IntentAdmissionPolicy::All,
        )
        .expect("prepare projection");

        assert_eq!(effects.next_context.needs.len(), 1);
        assert_eq!(effects.context_delta.added_needs.len(), 1);
        assert_eq!(effects.pipeline.intents.len(), 1);
        assert_eq!(effects.pipeline.intents[0].kind.as_str(), "observed");
    }

    #[test]
    fn prepare_projection_errors_when_context_keeps_growing() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let target = Fact::new(FactScope::Global, 1, b"unbounded".to_vec());
        let role = Role::new("exact").unwrap();

        for index in 0..=PROJECTION_CONTEXT_FIXPOINT_LIMIT {
            let offered = Fact::new(FactScope::Global, index as u64 + 2, vec![index as u8]);
            submit_fact_to_store(&store, offered.clone()).expect("persist offer payload");
            let offer = ContextOffer {
                owner: offered.id,
                role: role.clone(),
                scope: target.scope.clone(),
                start_key: ContextKey::from_bytes(vec![index as u8]),
                end_key: ContextKey::from_bytes(vec![index as u8]),
            };
            crate::core::pipeline::context_store::insert_context_offer_for_test(&store, &offer)
                .expect("insert stored offer");
        }

        let pending = PendingFact {
            source: ProjectionSource::Durable,
            fact_id: target.id,
            fact: target,
            previous_context: ContextSet::new(),
            projection_context: ProjectionContext::default(),
        };
        let err = match prepare_projection_effects(
            &GrowingNeedProjector { role },
            pending,
            &store,
            &[],
            None,
            IntentAdmissionPolicy::All,
        ) {
            Ok(_) => panic!("projection should hit fixed-point bound"),
            Err(err) => err,
        };

        assert!(err.contains("did not settle"));
    }

    #[test]
    fn ephemeral_input_projects_child_fact_immediately() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let parent = Fact::new(FactScope::Local, 1, b"ephemeral-parent".to_vec());
        let child = Fact::new(FactScope::Global, 2, b"child-offer".to_vec());
        store
            .write_transaction(|tx| {
                crate::core::fact_store::insert_ephemeral_fact_in_tx(tx, &parent)
            })
            .expect("insert ephemeral input");

        let progress = drain_pending_projection(
            &ParentChildProjector {
                parent_id: parent.id,
                child: child.clone(),
                child_mode: ChildMode::Offer,
            },
            &store,
            &[],
            None,
            10,
        )
        .expect("drain projection");

        assert_eq!(progress.projected, 1);
        assert!(
            crate::core::fact_store::ephemeral_fact_by_id(&store, &parent.id)
                .expect("load ephemeral")
                .is_none()
        );
        assert_eq!(
            crate::core::fact_store::persisted_fact(&store, &child.id)
                .expect("load child")
                .as_ref(),
            Some(&child)
        );
        let child_context = stored_context_for_owner(&store, &child.id).expect("child context");
        assert_eq!(child_context.offers.len(), 1);
        assert!(child_context.needs.is_empty());
    }

    #[test]
    fn ephemeral_input_missing_context_is_discarded_without_parking() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let parent = Fact::new(FactScope::Local, 1, b"ephemeral-need".to_vec());
        store
            .write_transaction(|tx| {
                crate::core::fact_store::insert_ephemeral_fact_in_tx(tx, &parent)
            })
            .expect("insert ephemeral input");

        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([7; 32]);
        let progress = drain_pending_projection(
            &EphemeralNeedOnly {
                role: role.clone(),
                key: key.clone(),
            },
            &store,
            &[],
            None,
            10,
        )
        .expect("ephemeral unresolved needs are transient");

        assert_eq!(progress.projected, 1);
        assert!(
            crate::core::fact_store::ephemeral_fact_by_id(&store, &parent.id)
                .expect("load ephemeral")
                .is_none()
        );
        let context = stored_context_for_owner(&store, &parent.id).expect("parent context");
        assert!(context.needs.is_empty());
        assert!(context.offers.is_empty());
    }

    #[test]
    fn ephemeral_input_can_use_existing_durable_context() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let parent = Fact::new(FactScope::Local, 1, b"ephemeral-context".to_vec());
        let offered = Fact::new(FactScope::Global, 2, b"available".to_vec());
        submit_fact_to_store(&store, offered.clone()).expect("persist offer payload");
        store
            .conn()
            .execute(
                "DELETE FROM pending_projection WHERE owner = ?1",
                rusqlite::params![offered.id.as_slice()],
            )
            .expect("clear offered fact pending row");
        store
            .write_transaction(|tx| {
                crate::core::fact_store::insert_ephemeral_fact_in_tx(tx, &parent)
            })
            .expect("insert ephemeral input");

        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([8; 32]);
        let offer = ContextOffer {
            owner: offered.id,
            role: role.clone(),
            scope: parent.scope.clone(),
            start_key: key.clone(),
            end_key: key.clone(),
        };
        crate::core::pipeline::context_store::insert_context_offer_for_test(&store, &offer)
            .expect("insert stored offer");

        let progress = drain_pending_projection(
            &EphemeralIntentAfterContext {
                role: role.clone(),
                key: key.clone(),
            },
            &store,
            &[],
            None,
            10,
        )
        .expect("drain projection");

        assert_eq!(progress.projected, 1);
        assert!(
            crate::core::fact_store::ephemeral_fact_by_id(&store, &parent.id)
                .expect("load ephemeral")
                .is_none()
        );
        let context = stored_context_for_owner(&store, &parent.id).expect("parent context");
        assert!(context.needs.is_empty());
        assert!(context.offers.is_empty());
    }

    #[test]
    fn ephemeral_input_cannot_emit_effects_while_transient_needs_remain() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let parent = Fact::new(FactScope::Local, 1, b"ephemeral-partial".to_vec());
        store
            .write_transaction(|tx| {
                crate::core::fact_store::insert_ephemeral_fact_in_tx(tx, &parent)
            })
            .expect("insert ephemeral input");

        let err = drain_pending_projection(
            &EphemeralNeedAndIntentProjector {
                role: Role::new("exact").unwrap(),
                key: ContextKey::from_bytes([9; 32]),
            },
            &store,
            &[],
            None,
            10,
        )
        .expect_err("ephemeral inputs cannot partially succeed with unresolved probes");

        assert!(err.contains("transient needs remain"), "{err}");
        assert!(
            crate::core::fact_store::ephemeral_fact_by_id(&store, &parent.id)
                .expect("load ephemeral")
                .is_some()
        );
        let context = stored_context_for_owner(&store, &parent.id).expect("parent context");
        assert!(context.needs.is_empty());
        assert!(context.offers.is_empty());
    }

    #[test]
    fn ephemeral_input_cannot_emit_durable_offers() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let parent = Fact::new(FactScope::Local, 1, b"ephemeral-offer".to_vec());
        store
            .write_transaction(|tx| {
                crate::core::fact_store::insert_ephemeral_fact_in_tx(tx, &parent)
            })
            .expect("insert ephemeral input");

        let err = drain_pending_projection(&EphemeralOfferProjector, &store, &[], None, 10)
            .expect_err("ephemeral offers should fail");

        assert!(err.contains("ephemeral projection input cannot emit durable offers"));
        assert!(
            crate::core::fact_store::ephemeral_fact_by_id(&store, &parent.id)
                .expect("load ephemeral")
                .is_some()
        );
    }

    #[test]
    fn child_fact_parking_counts_as_successful_parent_projection() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let parent = Fact::new(FactScope::Local, 1, b"ephemeral-parent".to_vec());
        let child = Fact::new(FactScope::Global, 2, b"child-need".to_vec());
        store
            .write_transaction(|tx| {
                crate::core::fact_store::insert_ephemeral_fact_in_tx(tx, &parent)
            })
            .expect("insert ephemeral input");

        let progress = drain_pending_projection(
            &ParentChildProjector {
                parent_id: parent.id,
                child: child.clone(),
                child_mode: ChildMode::Need,
            },
            &store,
            &[],
            None,
            10,
        )
        .expect("drain projection");

        assert_eq!(progress.projected, 1);
        assert!(
            crate::core::fact_store::ephemeral_fact_by_id(&store, &parent.id)
                .expect("load ephemeral")
                .is_none()
        );
        assert!(crate::core::fact_store::persisted_fact(&store, &child.id)
            .expect("load child")
            .is_some());
        let child_context = stored_context_for_owner(&store, &child.id).expect("child context");
        assert_eq!(child_context.needs.len(), 1);
        assert!(child_context.offers.is_empty());
    }

    #[test]
    fn child_fact_projection_error_rolls_back_parent_projection() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let parent = Fact::new(FactScope::Local, 1, b"ephemeral-parent".to_vec());
        let child = Fact::new(FactScope::Global, 2, b"child-error".to_vec());
        store
            .write_transaction(|tx| {
                crate::core::fact_store::insert_ephemeral_fact_in_tx(tx, &parent)
            })
            .expect("insert ephemeral input");

        let err = drain_pending_projection(
            &ParentChildProjector {
                parent_id: parent.id,
                child: child.clone(),
                child_mode: ChildMode::Error,
            },
            &store,
            &[],
            None,
            10,
        )
        .expect_err("child projection should fail");

        assert!(err.contains("child projection failed"));
        assert!(
            crate::core::fact_store::ephemeral_fact_by_id(&store, &parent.id)
                .expect("load ephemeral")
                .is_some()
        );
        assert!(crate::core::fact_store::persisted_fact(&store, &child.id)
            .expect("load child")
            .is_none());
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

    fn drain_pending_projection(
        projector: &impl Projector,
        store: &Store,
        allowed_tables: &[TableName],
        fact_admission: Option<FactAdmissionFn>,
        limit: usize,
    ) -> Result<super::super::ProjectionProgress, String> {
        super::super::PipelineEngine::new(store, projector, allowed_tables, fact_admission)
            .drain_projection(limit)
    }

    fn intent_payload_for(store: &Store, kind: &str, key: &FactId) -> Vec<u8> {
        store
            .conn()
            .query_row(
                "SELECT payload FROM intents WHERE kind = ?1 AND idempotence_key = ?2",
                rusqlite::params![kind, key.as_slice()],
                |row| row.get(0),
            )
            .expect("load intent payload")
    }

    fn pending_projection_count(store: &Store, owner: FactId) -> i64 {
        store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pending_projection WHERE owner = ?1",
                rusqlite::params![owner.as_slice()],
                |row| row.get(0),
            )
            .expect("count pending projection")
    }

    fn context_edge_count(store: &Store, owner: FactId) -> i64 {
        store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM context_edges WHERE owner = ?1",
                rusqlite::params![owner.as_slice()],
                |row| row.get(0),
            )
            .expect("count context edges")
    }

    struct NeedUntilOffer {
        role: Role,
        key: ContextKey,
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
                    start_key: self.key.clone(),
                    end_key: self.key.clone(),
                }))
            } else {
                Ok(ProjectionOutput::new().intent(Intent::new(
                    self.intent_kind.clone(),
                    fact.id,
                    context
                        .offers()
                        .first()
                        .map(|offer| offer.owner)
                        .unwrap_or(fact.id),
                )))
            }
        }
    }

    struct PrematureNeedUntilPayload {
        role: Role,
        key: ContextKey,
    }

    impl Projector for PrematureNeedUntilPayload {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            let need = ContextNeed {
                owner: fact.id,
                role: self.role.clone(),
                scope: fact.scope.clone(),
                start_key: self.key.clone(),
                end_key: self.key.clone(),
            };

            if let Some(payload) = context.payload_for(&need) {
                Ok(ProjectionOutput::new().intent(Intent::new(
                    IntentKind::new("ready").unwrap(),
                    fact.id,
                    payload.id,
                )))
            } else {
                Ok(ProjectionOutput::new().need(need).intent(Intent::new(
                    IntentKind::new("premature").unwrap(),
                    fact.id,
                    b"missing".to_vec(),
                )))
            }
        }
    }

    struct SameBatchDependencyProjector {
        offered_id: FactId,
        dependent_id: FactId,
        role: Role,
        key: ContextKey,
    }

    impl Projector for SameBatchDependencyProjector {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            if fact.id == self.offered_id {
                return Ok(ProjectionOutput::new().offer(ContextOffer {
                    owner: fact.id,
                    role: self.role.clone(),
                    scope: fact.scope.clone(),
                    start_key: self.key.clone(),
                    end_key: self.key.clone(),
                }));
            }

            if fact.id != self.dependent_id {
                return Ok(ProjectionOutput::new());
            }

            let need = ContextNeed {
                owner: fact.id,
                role: self.role.clone(),
                scope: fact.scope.clone(),
                start_key: self.key.clone(),
                end_key: self.key.clone(),
            };
            if let Some(payload) = context.payload_for(&need) {
                Ok(ProjectionOutput::new().intent(Intent::new(
                    IntentKind::new("same_batch_ready").unwrap(),
                    fact.id,
                    payload.id,
                )))
            } else {
                Ok(ProjectionOutput::new().need(need))
            }
        }
    }

    struct RollbackBatchProjector {
        offered_id: FactId,
        failing_id: FactId,
        role: Role,
        key: ContextKey,
    }

    impl Projector for RollbackBatchProjector {
        fn project(
            &self,
            fact: &Fact,
            _context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            if fact.id == self.offered_id {
                return Ok(ProjectionOutput::new().offer(ContextOffer {
                    owner: fact.id,
                    role: self.role.clone(),
                    scope: fact.scope.clone(),
                    start_key: self.key.clone(),
                    end_key: self.key.clone(),
                }));
            }
            if fact.id == self.failing_id {
                return Err("batch projection failed".to_string());
            }
            Ok(ProjectionOutput::new())
        }
    }

    /// `failing_id` authenticates fine (it parks when its context is absent) but
    /// errors once its dependency context is present — an authentic fact with
    /// inconsistent context.
    struct ContextInconsistentProjector {
        offered_id: FactId,
        failing_id: FactId,
        role: Role,
        key: ContextKey,
    }

    impl Projector for ContextInconsistentProjector {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            if fact.id == self.offered_id {
                return Ok(ProjectionOutput::new().offer(ContextOffer {
                    owner: fact.id,
                    role: self.role.clone(),
                    scope: fact.scope.clone(),
                    start_key: self.key.clone(),
                    end_key: self.key.clone(),
                }));
            }
            if fact.id == self.failing_id {
                let need = ContextNeed {
                    owner: fact.id,
                    role: self.role.clone(),
                    scope: fact.scope.clone(),
                    start_key: self.key.clone(),
                    end_key: self.key.clone(),
                };
                if context.payload_for(&need).is_some() {
                    return Err("context inconsistent".to_string());
                }
                return Ok(ProjectionOutput::new().need(need));
            }
            Ok(ProjectionOutput::new())
        }
    }

    struct WatchNeedProjector {
        role: Role,
        key: ContextKey,
    }

    impl Projector for WatchNeedProjector {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            let need = ContextNeed {
                owner: fact.id,
                role: self.role.clone(),
                scope: fact.scope.clone(),
                start_key: self.key.clone(),
                end_key: self.key.clone(),
            };
            let mut output = ProjectionOutput::new().need(need.clone());
            if context.payload_for(&need).is_some() {
                output = output.intent(Intent::new(
                    IntentKind::new("observed").unwrap(),
                    fact.id,
                    b"watched".to_vec(),
                ));
            }
            Ok(output)
        }
    }

    struct GrowingNeedProjector {
        role: Role,
    }

    impl Projector for GrowingNeedProjector {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            let next_selector = vec![context.offers().len() as u8];
            Ok(ProjectionOutput::new().need(ContextNeed {
                owner: fact.id,
                role: self.role.clone(),
                scope: fact.scope.clone(),
                start_key: ContextKey::from_bytes(next_selector.clone()),
                end_key: ContextKey::from_bytes(next_selector),
            }))
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
                start_key: ContextKey::from_bytes(fact.id),
                end_key: ContextKey::from_bytes(fact.id),
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
                start_key: ContextKey::from_bytes(fact.id),
                end_key: ContextKey::from_bytes(fact.id),
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

    struct BadPurgeOwnerProjector;

    impl Projector for BadPurgeOwnerProjector {
        fn project(
            &self,
            _fact: &Fact,
            _context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            Ok(ProjectionOutput::new().purge_self([9; 32]))
        }
    }

    struct SelfPurgeProjector;

    impl Projector for SelfPurgeProjector {
        fn project(
            &self,
            fact: &Fact,
            _context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            Ok(ProjectionOutput::new().purge_self(fact.id))
        }
    }

    enum ChildMode {
        Offer,
        Need,
        Error,
    }

    struct ParentChildProjector {
        parent_id: FactId,
        child: Fact,
        child_mode: ChildMode,
    }

    impl Projector for ParentChildProjector {
        fn project(
            &self,
            fact: &Fact,
            _context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            if fact.id == self.parent_id {
                return Ok(ProjectionOutput::new().fact(self.child.clone()));
            }
            if fact.id != self.child.id {
                return Ok(ProjectionOutput::new());
            }
            match self.child_mode {
                ChildMode::Offer => Ok(ProjectionOutput::new().offer(ContextOffer {
                    owner: fact.id,
                    role: Role::new("child_ready").unwrap(),
                    scope: fact.scope.clone(),
                    start_key: ContextKey::from_bytes(fact.id),
                    end_key: ContextKey::from_bytes(fact.id),
                })),
                ChildMode::Need => Ok(ProjectionOutput::new().need(ContextNeed {
                    owner: fact.id,
                    role: Role::new("missing_child_context").unwrap(),
                    scope: fact.scope.clone(),
                    start_key: ContextKey::from_bytes(fact.id),
                    end_key: ContextKey::from_bytes(fact.id),
                })),
                ChildMode::Error => Err("child projection failed".to_string()),
            }
        }
    }

    struct EphemeralNeedOnly {
        role: Role,
        key: ContextKey,
    }

    impl Projector for EphemeralNeedOnly {
        fn project(
            &self,
            fact: &Fact,
            _context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            Ok(ProjectionOutput::new().need(ContextNeed {
                owner: fact.id,
                role: self.role.clone(),
                scope: fact.scope.clone(),
                start_key: self.key.clone(),
                end_key: self.key.clone(),
            }))
        }
    }

    struct EphemeralIntentAfterContext {
        role: Role,
        key: ContextKey,
    }

    impl Projector for EphemeralIntentAfterContext {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            let need = ContextNeed {
                owner: fact.id,
                role: self.role.clone(),
                scope: fact.scope.clone(),
                start_key: self.key.clone(),
                end_key: self.key.clone(),
            };
            if let Some(payload) = context.payload_for(&need) {
                Ok(ProjectionOutput::new().intent(Intent::new(
                    IntentKind::new("ephemeral_ready").unwrap(),
                    fact.id,
                    payload.id,
                )))
            } else {
                Ok(ProjectionOutput::new().need(need))
            }
        }
    }

    struct EphemeralOfferProjector;

    impl Projector for EphemeralOfferProjector {
        fn project(
            &self,
            fact: &Fact,
            _context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            Ok(ProjectionOutput::new().offer(ContextOffer {
                owner: fact.id,
                role: Role::new("ephemeral_offer").unwrap(),
                scope: fact.scope.clone(),
                start_key: ContextKey::from_bytes(fact.id),
                end_key: ContextKey::from_bytes(fact.id),
            }))
        }
    }

    struct EphemeralNeedAndIntentProjector {
        role: Role,
        key: ContextKey,
    }

    impl Projector for EphemeralNeedAndIntentProjector {
        fn project(
            &self,
            fact: &Fact,
            _context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            Ok(ProjectionOutput::new()
                .need(ContextNeed {
                    owner: fact.id,
                    role: self.role.clone(),
                    scope: fact.scope.clone(),
                    start_key: self.key.clone(),
                    end_key: self.key.clone(),
                })
                .intent(Intent::new(
                    IntentKind::new("ephemeral_partial").unwrap(),
                    fact.id,
                    Vec::new(),
                )))
        }
    }
}
