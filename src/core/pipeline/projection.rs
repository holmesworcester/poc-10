//! One-item fact projection.
//!
//! A projection item loads one fact, its standing context, any matched payload
//! facts, and due time ranges. It then runs the protocol projector, resolves
//! any newly declared needs that already match stored offers, and commits the
//! settled output once.
//!
//! Queue recursion is explicit outside this item. If projection emits child
//! facts, shared effect commit stores them in `pending_projection`; if a later
//! item creates a matching offer, context fanout requeues the dependent owner.
//! `projection_queue` later processes that work like any other fact.

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
const PROJECTION_CONTEXT_RESOLUTION_LIMIT: usize = 8;

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
/// value that says what should happen if the projection commits. The projector
/// may first declare needs; core then loads already-stored matching offers into
/// this item's in-memory context and reruns until that context stops growing.
/// Later offers still use ordinary context wake fanout through the queue.
pub(super) fn prepare_projection_effects(
    store: &Store,
    projector: &(impl Projector + ?Sized),
    pending_fact: PendingFact,
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
    let run = resolve_projection_context(
        store,
        projector,
        &fact,
        &previous_context,
        &mut projection_context,
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

fn resolve_projection_context(
    store: &Store,
    projector: &(impl Projector + ?Sized),
    fact: &Fact,
    previous_context: &ContextSet,
    projection_context: &mut ProjectionContext,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    intent_policy: IntentAdmissionPolicy<'_>,
) -> Result<ProjectionRun, String> {
    for _ in 0..PROJECTION_CONTEXT_RESOLUTION_LIMIT {
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

        let matched_context =
            crate::core::perf_profile::measure_result("projection_context_match", || {
                stored_matching_context(store, &run.context)
            })?;
        if !projection_context.extend_with_matches(matched_context) {
            return Ok(run);
        }
    }

    Err(format!(
        "projection context for fact {:x?} did not settle after {PROJECTION_CONTEXT_RESOLUTION_LIMIT} runs",
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
/// Ephemeral inputs are one-shot. They may emit needs as transient probes, but
/// they cannot leave standing offers or time wakes behind after the projection
/// commits.
pub(super) fn commit_projection_effects(
    store: &Store,
    effects: &ProjectionEffects,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
) -> Result<usize, String> {
    store
        .write_transaction(|tx| {
            let suppressed_intents =
                crate::core::perf_profile::measure_result("projection_commit_tx_body", || {
                    commit_projection_effects_in_tx(tx, effects, allowed_tables, fact_admission)
                })?;
            Ok(suppressed_intents)
        })
        .map_err(|err| format!("commit projection effects: {err}"))
}

pub(super) fn commit_projection_effects_in_tx(
    tx: &Store,
    effects: &ProjectionEffects,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
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

    crate::core::perf_profile::measure_result("projection_commit_pipeline_effects", || {
        commit_pipeline_effects_in_tx(tx, &effects.pipeline, allowed_tables, fact_admission)
    })?;
    Ok(effects.suppressed_intents)
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
pub(super) fn pending_durable_fact_ids(store: &Store, limit: usize) -> Result<Vec<FactId>, String> {
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
pub(super) fn pending_ephemeral_fact_ids(
    store: &Store,
    limit: usize,
) -> Result<Vec<FactId>, String> {
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
        let projector = test_projector(|fact: &Fact, _context: &ProjectionContext| {
            Ok(ProjectionOutput::new().offer(ContextOffer {
                owner: [9; 32],
                role: Role::new("exact").unwrap(),
                scope: fact.scope.clone(),
                start_key: ContextKey::from_bytes(fact.id),
                end_key: ContextKey::from_bytes(fact.id),
            }))
        });

        let err = run_projection(&projector, &fact, &ContextSet::new(), Vec::new())
            .expect_err("projection should reject foreign offer owner");

        assert!(err.contains("projector emitted offer with owner"));
    }

    #[test]
    fn projection_run_rejects_need_owned_by_another_fact() {
        let fact = Fact::new(FactScope::Global, 1, b"owned".to_vec());
        let projector = test_projector(|fact: &Fact, _context: &ProjectionContext| {
            Ok(ProjectionOutput::new().need(ContextNeed {
                owner: [9; 32],
                role: Role::new("exact").unwrap(),
                scope: fact.scope.clone(),
                start_key: ContextKey::from_bytes(fact.id),
                end_key: ContextKey::from_bytes(fact.id),
            }))
        });

        let err = run_projection(&projector, &fact, &ContextSet::new(), Vec::new())
            .expect_err("projection should reject foreign need owner");

        assert!(err.contains("projector emitted need with owner"));
    }

    #[test]
    fn projection_run_rejects_time_wake_owned_by_another_fact() {
        let fact = Fact::new(FactScope::Global, 1, b"owned".to_vec());
        let projector = test_projector(|_fact: &Fact, _context: &ProjectionContext| {
            Ok(ProjectionOutput::new().time_wake(TimeWake {
                owner: [9; 32],
                timeline: Timeline::new("test").unwrap(),
                at: 1,
            }))
        });

        let err = run_projection(&projector, &fact, &ContextSet::new(), Vec::new())
            .expect_err("projection should reject foreign time-wake owner");

        assert!(err.contains("projector emitted time wake"));
    }

    #[test]
    fn projection_run_rejects_purge_owned_by_another_fact() {
        let fact = Fact::new(FactScope::Global, 1, b"owned".to_vec());
        let projector = test_projector(|_fact: &Fact, _context: &ProjectionContext| {
            Ok(ProjectionOutput::new().purge_self([9; 32]))
        });

        let err = run_projection(&projector, &fact, &ContextSet::new(), Vec::new())
            .expect_err("projection should reject foreign purge owner");

        assert!(err.contains("projector tried to purge fact"));
    }

    #[test]
    fn projection_run_allows_self_purge() {
        let fact = Fact::new(FactScope::Global, 1, b"owned".to_vec());
        let projector = test_projector(|fact: &Fact, _context: &ProjectionContext| {
            Ok(ProjectionOutput::new().purge_self(fact.id))
        });

        let run = run_projection(&projector, &fact, &ContextSet::new(), Vec::new())
            .expect("projection should allow self purge");

        assert_eq!(run.pipeline.purged_facts, vec![fact.id]);
    }

    #[test]
    fn projection_run_diffs_standing_context_without_self_waking() {
        let fact = Fact::new(FactScope::Global, 1, b"stable".to_vec());
        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([9; 32]);
        let projector = need_until_offer(role, key, IntentKind::new("followup").unwrap());

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
        let projector = need_until_offer(
            role.clone(),
            key.clone(),
            IntentKind::new("followup").unwrap(),
        );
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
    fn projection_drain_resolves_new_need_that_matches_existing_offer() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let target = Fact::new(FactScope::Global, 1, b"target".to_vec());
        let offered = Fact::new(FactScope::Global, 2, b"available".to_vec());
        submit_fact_to_store(&store, offered.clone()).expect("persist offer payload");
        submit_fact_to_store(&store, target.clone()).expect("persist target");
        store
            .conn()
            .execute(
                "DELETE FROM pending_projection WHERE owner = ?1",
                rusqlite::params![offered.id.as_slice()],
            )
            .expect("clear offered fact pending row");

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

        let projector = need_until_payload(role, key, "ready", Some("premature"));
        let progress =
            drain_projection(&projector, &store, &[], None, 2).expect("drain projection");

        assert_eq!(progress.projected, 1);
        assert_eq!(
            intent_payload_for(&store, "ready", &target.id),
            offered.id.to_vec()
        );
        let target_context = stored_context_for_owner(&store, &target.id).expect("target context");
        assert!(target_context.needs.is_empty());
        assert_eq!(pending_projection_count(&store, target.id), 0);
    }

    #[test]
    fn projection_drain_resolves_new_range_need_that_matches_existing_offer() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let target = Fact::new(FactScope::Global, 1, b"target".to_vec());
        let offered = Fact::new(FactScope::Global, 2, b"custom".to_vec());
        submit_fact_to_store(&store, offered.clone()).expect("persist offer payload");
        submit_fact_to_store(&store, target.clone()).expect("persist target");
        store
            .conn()
            .execute(
                "DELETE FROM pending_projection WHERE owner = ?1",
                rusqlite::params![offered.id.as_slice()],
            )
            .expect("clear offered fact pending row");

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

        let projector = need_until_payload(role, key, "ready", Some("premature"));
        let progress =
            drain_projection(&projector, &store, &[], None, 2).expect("drain projection");

        assert_eq!(progress.projected, 1);
        assert_eq!(
            intent_payload_for(&store, "ready", &target.id),
            offered.id.to_vec()
        );
    }

    #[test]
    fn projection_queue_revisits_dependent_after_offer_commits() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let offered = Fact::new(FactScope::Global, 1, b"queue-offer".to_vec());
        let dependent = Fact::new(FactScope::Global, 2, b"queue-dependent".to_vec());
        submit_fact_to_store(&store, dependent.clone()).expect("submit dependent first");

        let role = Role::new("queue_dep").unwrap();
        let key = ContextKey::from_bytes(b"shared-key");
        let projector = QueueDependencyProjector {
            offered_id: offered.id,
            dependent_id: dependent.id,
            role: role.clone(),
            key: key.clone(),
        };
        let first = drain_projection(&projector, &store, &[], None, 1)
            .expect("dependent parks on missing offer");

        assert_eq!(first.projected, 1);
        assert_eq!(pending_projection_count(&store, dependent.id), 0);
        let parked_context = stored_context_for_owner(&store, &dependent.id).expect("parked");
        assert_eq!(parked_context.needs.len(), 1);

        submit_fact_to_store(&store, offered.clone()).expect("submit offer");
        let progress =
            drain_projection(&projector, &store, &[], None, 3).expect("drain queued dependency");

        assert_eq!(progress.projected, 2);
        let payload = intent_payload_for(&store, "queue_ready", &dependent.id);
        assert_eq!(payload, offered.id.to_vec());
        let dependent_context =
            stored_context_for_owner(&store, &dependent.id).expect("dependent context");
        assert!(dependent_context.needs.is_empty());
        assert_eq!(pending_projection_count(&store, offered.id), 0);
        assert_eq!(pending_projection_count(&store, dependent.id), 0);
    }

    #[test]
    fn projection_queue_isolates_a_failed_fact_without_rolling_back_previous_items() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let offered = Fact::new(FactScope::Global, 1, b"rollback-queue-offer".to_vec());
        let failing = Fact::new(FactScope::Global, 2, b"rollback-queue-fail".to_vec());
        assert_eq!(
            submit_facts_to_store(&store, vec![offered.clone(), failing.clone()])
                .expect("submit pending facts"),
            2
        );

        let progress = drain_projection(
            &ProjectionFailureProjector {
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
        .expect("a failed fact must not undo earlier projected items");

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
    fn projection_queue_keeps_a_context_inconsistent_fact_as_evidence() {
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

        let progress = drain_projection(
            &ContextInconsistentProjector {
                offered_id: offered.id,
                failing_id: failing.id,
                role: Role::new("inconsistent_dep").unwrap(),
                key: ContextKey::from_bytes(b"inconsistent-key"),
            },
            &store,
            &[],
            None,
            3,
        )
        .expect("a context-inconsistent fact must not undo earlier projected items");

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
    fn projection_drain_can_keep_watch_need_after_it_matches() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let target = Fact::new(FactScope::Global, 1, b"watcher".to_vec());
        let offered = Fact::new(FactScope::Global, 2, b"watched".to_vec());
        submit_fact_to_store(&store, offered.clone()).expect("persist offer payload");
        submit_fact_to_store(&store, target.clone()).expect("persist target");
        store
            .conn()
            .execute(
                "DELETE FROM pending_projection WHERE owner = ?1",
                rusqlite::params![offered.id.as_slice()],
            )
            .expect("clear offered fact pending row");

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

        let projector = watch_need(role, key, "observed");
        let progress =
            drain_projection(&projector, &store, &[], None, 2).expect("drain projection");

        assert_eq!(progress.projected, 2);
        assert_eq!(
            intent_payload_for(&store, "observed", &target.id),
            b"watched".to_vec()
        );
        let target_context = stored_context_for_owner(&store, &target.id).expect("target context");
        assert_eq!(target_context.needs.len(), 1);
        assert_eq!(pending_projection_count(&store, target.id), 0);
    }

    #[test]
    fn ephemeral_input_queues_child_fact_for_projection() {
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

        let progress = drain_projection(
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

        assert_eq!(progress.projected, 2);
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
        let projector = need_only(role.clone(), key.clone());
        let progress = drain_projection(&projector, &store, &[], None, 10)
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

        let projector = need_until_payload(role.clone(), key.clone(), "ephemeral_ready", None);
        let progress =
            drain_projection(&projector, &store, &[], None, 10).expect("drain projection");

        assert_eq!(progress.projected, 1);
        assert!(
            crate::core::fact_store::ephemeral_fact_by_id(&store, &parent.id)
                .expect("load ephemeral")
                .is_none()
        );
        let context = stored_context_for_owner(&store, &parent.id).expect("parent context");
        assert!(context.needs.is_empty());
        assert!(context.offers.is_empty());
        assert_eq!(
            intent_payload_for(&store, "ephemeral_ready", &parent.id),
            offered.id.to_vec()
        );
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

        let projector = need_and_intent(
            Role::new("exact").unwrap(),
            ContextKey::from_bytes([9; 32]),
            "ephemeral_partial",
        );
        let err = drain_projection(&projector, &store, &[], None, 10)
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

        let projector = self_offer(Role::new("ephemeral_offer").unwrap());
        let err = drain_projection(&projector, &store, &[], None, 10)
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

        let progress = drain_projection(
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

        assert_eq!(progress.projected, 2);
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
    fn child_fact_projection_error_isolated_after_parent_commits() {
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

        let progress = drain_projection(
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
        .expect("child projection rejection is isolated");

        assert_eq!(progress.projected, 1);
        assert!(
            crate::core::fact_store::ephemeral_fact_by_id(&store, &parent.id)
                .expect("load ephemeral")
                .is_none()
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

    fn drain_projection(
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

    fn need_for(fact: &Fact, role: &Role, key: &ContextKey) -> ContextNeed {
        ContextNeed {
            owner: fact.id,
            role: role.clone(),
            scope: fact.scope.clone(),
            start_key: key.clone(),
            end_key: key.clone(),
        }
    }

    fn offer_for(fact: &Fact, role: &Role, key: &ContextKey) -> ContextOffer {
        ContextOffer {
            owner: fact.id,
            role: role.clone(),
            scope: fact.scope.clone(),
            start_key: key.clone(),
            end_key: key.clone(),
        }
    }

    struct TestProjector<F> {
        project: F,
    }

    impl<F> Projector for TestProjector<F>
    where
        F: Fn(&Fact, &ProjectionContext) -> Result<ProjectionOutput, String>,
    {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            (self.project)(fact, context)
        }
    }

    fn test_projector<F>(project: F) -> TestProjector<F>
    where
        F: Fn(&Fact, &ProjectionContext) -> Result<ProjectionOutput, String>,
    {
        TestProjector { project }
    }

    fn need_until_offer(role: Role, key: ContextKey, intent_kind: IntentKind) -> impl Projector {
        test_projector(move |fact, context| {
            if context.offers().is_empty() {
                Ok(ProjectionOutput::new().need(need_for(fact, &role, &key)))
            } else {
                Ok(ProjectionOutput::new().intent(Intent::new(
                    intent_kind.clone(),
                    fact.id,
                    context
                        .offers()
                        .first()
                        .map(|offer| offer.owner)
                        .unwrap_or(fact.id),
                )))
            }
        })
    }

    fn need_until_payload(
        role: Role,
        key: ContextKey,
        ready_kind: &'static str,
        premature_kind: Option<&'static str>,
    ) -> impl Projector {
        test_projector(move |fact, context| {
            let need = need_for(fact, &role, &key);
            if let Some(payload) = context.payload_for(&need) {
                Ok(ProjectionOutput::new().intent(Intent::new(
                    IntentKind::new(ready_kind).unwrap(),
                    fact.id,
                    payload.id,
                )))
            } else {
                let mut output = ProjectionOutput::new().need(need);
                if let Some(kind) = premature_kind {
                    output = output.intent(Intent::new(
                        IntentKind::new(kind).unwrap(),
                        fact.id,
                        b"missing".to_vec(),
                    ));
                }
                Ok(output)
            }
        })
    }

    fn watch_need(role: Role, key: ContextKey, intent_kind: &'static str) -> impl Projector {
        test_projector(move |fact, context| {
            let need = need_for(fact, &role, &key);
            let mut output = ProjectionOutput::new().need(need.clone());
            if context.payload_for(&need).is_some() {
                output = output.intent(Intent::new(
                    IntentKind::new(intent_kind).unwrap(),
                    fact.id,
                    b"watched".to_vec(),
                ));
            }
            Ok(output)
        })
    }

    fn need_only(role: Role, key: ContextKey) -> impl Projector {
        test_projector(move |fact, _context| {
            Ok(ProjectionOutput::new().need(need_for(fact, &role, &key)))
        })
    }

    fn need_and_intent(role: Role, key: ContextKey, intent_kind: &'static str) -> impl Projector {
        test_projector(move |fact, _context| {
            Ok(ProjectionOutput::new()
                .need(need_for(fact, &role, &key))
                .intent(Intent::new(
                    IntentKind::new(intent_kind).unwrap(),
                    fact.id,
                    Vec::new(),
                )))
        })
    }

    fn self_offer(role: Role) -> impl Projector {
        test_projector(move |fact, _context| {
            let key = ContextKey::from_bytes(fact.id);
            Ok(ProjectionOutput::new().offer(offer_for(fact, &role, &key)))
        })
    }

    struct QueueDependencyProjector {
        offered_id: FactId,
        dependent_id: FactId,
        role: Role,
        key: ContextKey,
    }

    impl Projector for QueueDependencyProjector {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            if fact.id == self.offered_id {
                return Ok(ProjectionOutput::new().offer(offer_for(fact, &self.role, &self.key)));
            }

            if fact.id != self.dependent_id {
                return Ok(ProjectionOutput::new());
            }

            let need = need_for(fact, &self.role, &self.key);
            if let Some(payload) = context.payload_for(&need) {
                Ok(ProjectionOutput::new().intent(Intent::new(
                    IntentKind::new("queue_ready").unwrap(),
                    fact.id,
                    payload.id,
                )))
            } else {
                Ok(ProjectionOutput::new().need(need))
            }
        }
    }

    struct ProjectionFailureProjector {
        offered_id: FactId,
        failing_id: FactId,
        role: Role,
        key: ContextKey,
    }

    impl Projector for ProjectionFailureProjector {
        fn project(
            &self,
            fact: &Fact,
            _context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            if fact.id == self.offered_id {
                return Ok(ProjectionOutput::new().offer(offer_for(fact, &self.role, &self.key)));
            }
            if fact.id == self.failing_id {
                return Err("projection failed".to_string());
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
                return Ok(ProjectionOutput::new().offer(offer_for(fact, &self.role, &self.key)));
            }
            if fact.id == self.failing_id {
                let need = need_for(fact, &self.role, &self.key);
                if context.payload_for(&need).is_some() {
                    return Err("context inconsistent".to_string());
                }
                return Ok(ProjectionOutput::new().need(need));
            }
            Ok(ProjectionOutput::new())
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
                ChildMode::Offer => {
                    let role = Role::new("child_ready").unwrap();
                    let key = ContextKey::from_bytes(fact.id);
                    Ok(ProjectionOutput::new().offer(offer_for(fact, &role, &key)))
                }
                ChildMode::Need => {
                    let role = Role::new("missing_child_context").unwrap();
                    let key = ContextKey::from_bytes(fact.id);
                    Ok(ProjectionOutput::new().need(need_for(fact, &role, &key)))
                }
                ChildMode::Error => Err("child projection failed".to_string()),
            }
        }
    }
}
