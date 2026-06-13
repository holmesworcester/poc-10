//! One queued fact projection item.
//!
//! One item loads one fact, any matched payload facts, and due time ranges.
//! It then runs the routed protocol projector. The projector may decode raw
//! bytes, validate context, park on needs, and emit effects or offers. Core
//! resolves newly declared needs that already match stored offers and commits
//! the settled output once.
//!
//! Queue recursion is explicit outside this item. If projection emits child
//! facts, shared effect commit stores them in `pending_projection`; if a later
//! item creates a matching offer, context fanout requeues the dependent owner.
//! Runtime later drains that work like any other queued fact.

use self::commit_effects::{
    commit_pipeline_effects_in_tx, sqlite_string_error, validate_pipeline_effects_for_admission,
};
use self::context_store::{
    insert_context_need_in_tx, insert_context_offer_in_tx, pending_matching_context_for_owner,
    stored_context_for_owner, wake_context_matches_in_tx,
};
use crate::core::context::{diff_context_sets, ContextSet, ContextSetDelta};
use crate::core::effects::PipelineEffects;
use crate::core::facts::{Fact, FactId};
use crate::core::store::{
    candidate_fact_by_id, delete_candidate_fact_in_tx, move_candidate_to_retained_in_tx,
    persisted_fact, purge_fact_in_tx,
};
use crate::core::store::{Store, TableName};
use rusqlite::params;

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
fn isolate_rejected_durable_fact_in_tx(
    tx: &Store,
    fact_id: FactId,
    projector: &(impl Projector + ?Sized),
    mode: ProjectionMode,
) -> rusqlite::Result<()> {
    if durable_fact_fails_without_context(tx, fact_id, projector, mode) {
        purge_fact_in_tx(tx, fact_id)?;
        return Ok(());
    }
    tx.conn().execute(
        "DELETE FROM pending_projection WHERE owner = ?1",
        params![fact_id.as_slice()],
    )?;
    delete_pending_projection_matches_for_owner_in_tx(tx, fact_id)?;
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
    mode: ProjectionMode,
) -> bool {
    match persisted_fact(tx, &fact_id) {
        Ok(Some(fact)) => projector
            .project(&fact, &ProjectionContext::default().with_mode(mode))
            .is_err(),
        // Already gone, or unreadable: nothing to purge — just clear the marker.
        _ => false,
    }
}

/// Result of attempting one queued projection item.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ProjectionItemProgress {
    pub(crate) projected: bool,
    pub(crate) suppressed_intents: usize,
}

/// Run and commit one queued projection item.
///
/// Projection rejection consumes the queued item according to its source:
/// durable facts are either purged or isolated as context-inconsistent
/// evidence; candidate facts are dropped because they are one-shot.
pub(crate) fn process_projection_item(
    store: &Store,
    projector: &(impl Projector + ?Sized),
    pending_fact: PendingFact,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
) -> Result<ProjectionItemProgress, String> {
    let source = pending_fact.source;
    let fact_id = pending_fact.fact_id;
    let mode = pending_fact.mode;
    let effects =
        match crate::core::perf_profile::measure_result("projection_prepare_effects", || {
            prepare_projection_effects(
                store,
                projector,
                pending_fact,
                allowed_tables,
                fact_admission,
            )
        }) {
            Ok(effects) => effects,
            Err(_rejection) => {
                handle_rejected_projection(store, projector, source, fact_id, mode)?;
                return Ok(ProjectionItemProgress::default());
            }
        };
    let suppressed_intents =
        crate::core::perf_profile::measure_result("projection_commit_effects", || {
            commit_projection_effects(store, &effects, allowed_tables, fact_admission)
        })?;
    Ok(ProjectionItemProgress {
        projected: true,
        suppressed_intents,
    })
}

fn handle_rejected_projection(
    store: &Store,
    projector: &(impl Projector + ?Sized),
    source: ProjectionSource,
    fact_id: FactId,
    mode: ProjectionMode,
) -> Result<(), String> {
    match source {
        ProjectionSource::Durable => isolate_rejected_durable_fact(store, projector, fact_id, mode),
        ProjectionSource::Candidate => drop_rejected_candidate_fact(store, fact_id),
    }
}

fn isolate_rejected_durable_fact(
    store: &Store,
    projector: &(impl Projector + ?Sized),
    fact_id: FactId,
    mode: ProjectionMode,
) -> Result<(), String> {
    store
        .write_transaction(|tx| isolate_rejected_durable_fact_in_tx(tx, fact_id, projector, mode))
        .map_err(|err| format!("isolate rejected durable fact: {err}"))
}

/// Run the protocol projector for one fact and split its output.
///
/// No rows are written here. The result is an uncommitted `ProjectionEffects`
/// value that says what should happen if the projection commits. Projectors run
/// once over the context attached to the queued item; newly emitted needs only
/// wake a later queue item during commit.
fn prepare_projection_effects(
    _store: &Store,
    projector: &(impl Projector + ?Sized),
    pending_fact: PendingFact,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
) -> Result<ProjectionEffects, String> {
    let PendingFact {
        source,
        fact_id,
        mode,
        fact,
        previous_context,
        projection_context,
    } = pending_fact;
    let run = crate::core::perf_profile::measure_result("projection_projector_cpu", || {
        run_projection_with_context(projector, &fact, &previous_context, projection_context)
    })?;
    crate::core::perf_profile::measure_result("projection_validate_effects", || {
        validate_pipeline_effects_for_admission(&run.pipeline, allowed_tables, fact_admission)
    })?;
    Ok(ProjectionEffects {
        source,
        fact,
        fact_id,
        mode,
        retain_self: run.retain_self,
        next_context: run.context,
        next_time_wakes: run.time_wakes,
        context_delta: run.context_delta,
        pipeline: run.pipeline,
    })
}

/// The uncommitted output of projecting one pending fact.
struct ProjectionEffects {
    source: ProjectionSource,
    fact: Fact,
    fact_id: FactId,
    mode: ProjectionMode,
    retain_self: bool,
    next_context: ContextSet,
    next_time_wakes: Vec<TimeWake>,
    context_delta: ContextSetDelta,
    pipeline: PipelineEffects,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectionSource {
    Durable,
    Candidate,
}

/// Commit one pending fact's complete projection result.
///
/// This is the projection boundary, the same way `commit_handler_output` is the
/// dispatch boundary. The transaction consumes this fact's pending row and makes
/// the projector's output visible: replacement needs, append-only offers,
/// replacement time wakes, newly woken dependent facts, protocol row mutations,
/// and follow-up intents. If projection fails before this function, the pending
/// row remains queued. If anything fails inside this transaction, SQLite rolls
/// the whole boundary back.
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
/// Candidate facts are one-shot. They may emit needs as transient probes, but
/// they cannot leave standing offers or time wakes behind after the projection
/// commits.
fn commit_projection_effects(
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

fn commit_projection_effects_in_tx(
    tx: &Store,
    effects: &ProjectionEffects,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
) -> rusqlite::Result<usize> {
    let purges_self = effects.pipeline.purged_facts.contains(&effects.fact_id);
    let keep_projection_state = match effects.source {
        ProjectionSource::Durable => !purges_self,
        ProjectionSource::Candidate => effects.retain_self && !purges_self,
    };

    match effects.source {
        ProjectionSource::Durable => {
            crate::core::perf_profile::measure_result("projection_clear_pending", || {
                tx.conn().execute(
                    "DELETE FROM pending_projection WHERE owner = ?1",
                    params![effects.fact_id.as_slice()],
                )
            })?;
            crate::core::perf_profile::measure_result("projection_delete_pending_matches", || {
                delete_pending_projection_matches_for_owner_in_tx(tx, effects.fact_id)
            })?;
            crate::core::perf_profile::measure_result(
                "projection_delete_pending_time_ranges",
                || delete_pending_time_ranges_for_owner_in_tx(tx, effects.fact_id),
            )?;
        }
        ProjectionSource::Candidate => {
            if keep_projection_state {
                move_candidate_to_retained_in_tx(tx, &effects.fact)?;
            } else {
                validate_dropped_candidate_projection(effects).map_err(sqlite_string_error)?;
                crate::core::perf_profile::measure_result("projection_replace_context", || {
                    clear_stored_context_owner_rows(tx, effects.fact_id)
                })?;
                crate::core::perf_profile::measure_result(
                    "projection_delete_candidate_fact",
                    || delete_candidate_fact_in_tx(tx, effects.fact_id),
                )?;
            }
        }
    }

    if keep_projection_state {
        crate::core::perf_profile::measure_result("projection_replace_context", || {
            replace_needs_and_append_offers_for_owner(tx, effects.fact_id, &effects.next_context)
        })?;
        crate::core::perf_profile::measure_result("projection_replace_time_wakes", || {
            replace_stored_time_wake_owner_rows(tx, effects.fact_id, &effects.next_time_wakes)
        })?;
        crate::core::perf_profile::measure_result("projection_wake_context_matches", || {
            wake_context_matches_in_tx(tx, &effects.context_delta, effects.mode)
                .map_err(sqlite_string_error)
        })?;
    }

    crate::core::perf_profile::measure_result("projection_commit_pipeline_effects", || {
        commit_pipeline_effects_in_tx(
            tx,
            &effects.pipeline,
            allowed_tables,
            fact_admission,
            effects.mode,
        )
    })?;
    Ok(0)
}

fn validate_dropped_candidate_projection(effects: &ProjectionEffects) -> Result<(), String> {
    if !effects.next_context.offers.is_empty() {
        return Err("dropped candidate fact cannot emit durable offers".to_string());
    }
    if !effects.next_time_wakes.is_empty() {
        return Err("dropped candidate fact cannot emit time wakes".to_string());
    }
    if !effects.next_context.needs.is_empty() && !pipeline_effects_are_empty(&effects.pipeline) {
        return Err(
            "dropped candidate fact cannot emit effects while transient needs remain".to_string(),
        );
    }
    Ok(())
}

fn pipeline_effects_are_empty(effects: &PipelineEffects) -> bool {
    effects.facts.is_empty()
        && effects.candidate_facts.is_empty()
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

fn delete_pending_projection_matches_for_owner_in_tx(
    store: &Store,
    owner: FactId,
) -> rusqlite::Result<usize> {
    store.conn().execute(
        "DELETE FROM pending_projection_matches WHERE owner = ?1",
        params![owner.as_slice()],
    )
}

/// Replace this fact's standing needs and append its offers.
///
/// Needs are current subscriptions, so each successful durable projection
/// replaces the owner's need rows. Offers are durable evidence emitted by an
/// immutable fact, so they are inserted idempotently and remain until the fact
/// is purged.
fn replace_needs_and_append_offers_for_owner(
    store: &Store,
    owner: FactId,
    context: &ContextSet,
) -> rusqlite::Result<()> {
    store.conn().execute(
        "DELETE FROM context_edges WHERE owner = ?1 AND direction = 'need'",
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

/// Clear every context edge owned by this input id.
///
/// Candidate facts are one-shot and cannot leave standing durable
/// context. Durable fact purge also uses the storage layer's wider cleanup.
fn clear_stored_context_owner_rows(store: &Store, owner: FactId) -> rusqlite::Result<()> {
    store.conn().execute(
        "DELETE FROM context_edges WHERE owner = ?1",
        params![owner.as_slice()],
    )?;
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

/// A fact that has been claimed from the pending queue and is ready to project.
pub(crate) struct PendingFact {
    source: ProjectionSource,
    fact_id: FactId,
    mode: ProjectionMode,
    fact: Fact,
    previous_context: ContextSet,
    projection_context: ProjectionContext,
}

/// Load everything projection needs for one fact.
///
/// `previous_context` is the fact's standing context before this run.
/// `projection_context` is the matched input context exposed to the projector
/// for this run, including any due time ranges.
fn drop_rejected_candidate_fact(store: &Store, fact_id: FactId) -> Result<(), String> {
    store
        .write_transaction(|tx| delete_candidate_fact_in_tx(tx, fact_id))
        .map_err(|err| format!("drop rejected candidate fact: {err}"))?;
    Ok(())
}

pub(crate) fn load_pending_fact(
    store: &Store,
    source: ProjectionSource,
    fact_id: FactId,
    mode: ProjectionMode,
) -> Result<Option<PendingFact>, String> {
    let fact =
        crate::core::perf_profile::measure_result("projection_load_fact", || match source {
            ProjectionSource::Durable => persisted_fact(store, &fact_id),
            ProjectionSource::Candidate => candidate_fact_by_id(store, &fact_id),
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
            crate::core::perf_profile::measure_result("projection_load_pending_matches", || {
                pending_matching_context_for_owner(store, &fact_id)
            })?
            .with_time_ranges(time_ranges)
            .with_mode(mode)
        }
        ProjectionSource::Candidate => ProjectionContext::default().with_mode(mode),
    };
    Ok(Some(PendingFact {
        source,
        fact_id,
        mode,
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

/// Decode one due time range row stored by due time wake admission.
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

fn u64_column(value: i64, name: &str) -> rusqlite::Result<u64> {
    u64::try_from(value)
        .map_err(|_| rusqlite::Error::InvalidParameterName(format!("{name} is negative")))
}

/// The pure result of running one projector before any SQL writes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ProjectionRun {
    retain_self: bool,
    context: ContextSet,
    context_delta: ContextSetDelta,
    time_wakes: Vec<TimeWake>,
    pipeline: PipelineEffects,
}

/// Call the protocol projector and normalize the output for the SQL pipeline.
///
/// Projection output replaces current needs and appends durable offers for this
/// fact. This helper enforces that projectors only own their own context/time
/// rows and may purge only their own fact, then computes the context delta that
/// will wake dependent facts after commit.
fn run_projection_with_context(
    projector: &(impl Projector + ?Sized),
    fact: &Fact,
    previous_context: &ContextSet,
    context: ProjectionContext,
) -> Result<ProjectionRun, String> {
    let output = projector.project(fact, &context)?;
    enforce_owner_is_self(fact, &output)?;
    let context = append_offers_to_replacement_needs(previous_context, output.context_set());
    let context_delta = diff_context_sets(previous_context, &context);
    Ok(ProjectionRun {
        retain_self: output.retain_self,
        context,
        context_delta,
        time_wakes: output.time_wakes,
        pipeline: output.effects,
    })
}

fn append_offers_to_replacement_needs(
    previous_context: &ContextSet,
    output_context: ContextSet,
) -> ContextSet {
    ContextSet {
        needs: output_context.needs,
        offers: previous_context
            .offers
            .iter()
            .cloned()
            .chain(output_context.offers)
            .collect(),
    }
    .normalized()
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
mod contract_tests {
    use super::*;
    use crate::core::context::{ContextKey, ContextNeed, ContextOffer, Role};
    use crate::core::facts::{FactId, FactScope};
    use crate::core::intents::{Intent, IntentKind};
    use crate::core::project_fact::{submit_fact_to_store, submit_facts_to_store};
    use rusqlite::OptionalExtension;

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
    fn projection_run_keeps_previous_offers_when_projector_stops_emitting_them() {
        let fact = Fact::new(FactScope::Global, 1, b"offer-evidence".to_vec());
        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([4; 32]);
        let previous_offer = offer_for(&fact, &role, &key);
        let previous = ContextSet {
            needs: Vec::new(),
            offers: vec![previous_offer.clone()],
        }
        .normalized();
        let projector = test_projector(|_fact, _context| Ok(ProjectionOutput::new()));

        let next = run_projection(&projector, &fact, &previous, Vec::new())
            .expect("projection without re-emitting old offer");

        assert_eq!(next.context.offers, vec![previous_offer]);
        assert!(next.context_delta.removed_offers.is_empty());
    }

    #[test]
    fn projection_commit_keeps_existing_offer_when_owner_reprojects_without_it() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let fact = Fact::new(FactScope::Global, 1, b"stored-offer-evidence".to_vec());
        submit_fact_to_store(&store, fact.clone()).expect("persist fact");

        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([5; 32]);
        let offer = offer_for(&fact, &role, &key);
        crate::core::project_fact::context_store::insert_context_offer_for_test(&store, &offer)
            .expect("insert old offer");

        let projector = test_projector(|_fact, _context| Ok(ProjectionOutput::new()));
        let progress = drain_projection(&projector, &store, &[], None, 1)
            .expect("drain projection without re-emitting old offer");

        assert_eq!(progress.projected, 1);
        let context = stored_context_for_owner(&store, &fact.id).expect("stored context");
        assert!(context.needs.is_empty());
        assert_eq!(context.offers, vec![offer]);
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
        crate::core::project_fact::context_store::insert_context_offer_for_test(&store, &offer)
            .expect("insert stored offer");

        let projector = need_until_payload(role, key, "ready", Some("premature"));
        let progress =
            drain_projection(&projector, &store, &[], None, 2).expect("drain projection");

        assert_eq!(progress.projected, 2);
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
        crate::core::project_fact::context_store::insert_context_offer_for_test(&store, &offer)
            .expect("insert stored offer");

        let projector = need_until_payload(role, key, "ready", Some("premature"));
        let progress =
            drain_projection(&projector, &store, &[], None, 2).expect("drain projection");

        assert_eq!(progress.projected, 2);
        assert_eq!(
            intent_payload_for(&store, "ready", &target.id),
            offered.id.to_vec()
        );
    }

    #[test]
    fn projection_drain_revisits_dependent_after_offer_commits() {
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
    fn projection_drain_uses_context_attached_to_pending_queue() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let target = Fact::new(FactScope::Global, 1, b"queued-context-target".to_vec());
        let offered = Fact::new(FactScope::Global, 2, b"queued-context-payload".to_vec());
        submit_facts_to_store(&store, vec![target.clone(), offered.clone()])
            .expect("persist facts");
        for fact in [&target, &offered] {
            store
                .conn()
                .execute(
                    "DELETE FROM pending_projection WHERE owner = ?1",
                    rusqlite::params![fact.id.as_slice()],
                )
                .expect("clear initial pending row");
        }

        let role = Role::new("queued_ctx").unwrap();
        let key = ContextKey::from_bytes(b"queued-key");
        let need = need_for(&target, &role, &key);
        let offer = offer_for(&offered, &role, &key);
        store
            .write_transaction(|tx| {
                insert_context_need_in_tx(tx, &need)?;
                insert_context_offer_in_tx(tx, &offer)?;
                wake_context_matches_in_tx(
                    tx,
                    &ContextSetDelta {
                        added_offers: vec![offer.clone()],
                        ..ContextSetDelta::default()
                    },
                    ProjectionMode::Normal,
                )
                .map_err(sqlite_string_error)?;
                tx.conn().execute(
                    "DELETE FROM context_edges WHERE owner = ?1 AND direction = 'offer'",
                    rusqlite::params![offered.id.as_slice()],
                )?;
                Ok(())
            })
            .expect("queue match then remove standing offer");

        assert_eq!(pending_projection_match_count(&store, target.id), 1);
        let projector = need_until_payload(role, key, "queued_context_ready", None);
        let progress =
            drain_projection(&projector, &store, &[], None, 1).expect("drain projection");

        assert_eq!(progress.projected, 1);
        assert_eq!(
            intent_payload_for(&store, "queued_context_ready", &target.id),
            offered.id.to_vec()
        );
        assert_eq!(pending_projection_match_count(&store, target.id), 0);
    }

    #[test]
    fn projection_drain_attaches_all_satisfied_context_when_later_need_wakes() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let target = Fact::new(FactScope::Global, 1, b"multi-stage-target".to_vec());
        let first_offer = Fact::new(FactScope::Global, 2, b"multi-stage-first".to_vec());
        let second_offer = Fact::new(FactScope::Global, 3, b"multi-stage-second".to_vec());
        submit_fact_to_store(&store, target.clone()).expect("submit target");

        let projector = MultiStageDependencyProjector {
            target_id: target.id,
            first_offer_id: first_offer.id,
            second_offer_id: second_offer.id,
            first_role: Role::new("stage_first").unwrap(),
            first_key: ContextKey::from_bytes(b"first"),
            second_role: Role::new("stage_second").unwrap(),
            second_key: ContextKey::from_bytes(b"second"),
        };
        let first =
            drain_projection(&projector, &store, &[], None, 1).expect("target parks on first");

        assert_eq!(first.projected, 1);
        assert_eq!(pending_projection_count(&store, target.id), 0);

        submit_fact_to_store(&store, first_offer.clone()).expect("submit first offer");
        let second =
            drain_projection(&projector, &store, &[], None, 2).expect("first offer wakes target");

        assert_eq!(second.projected, 2);
        assert!(intent_payload_for_maybe(&store, "multi_stage_ready", &target.id).is_none());
        let staged_context = stored_context_for_owner(&store, &target.id).expect("target context");
        assert_eq!(staged_context.needs.len(), 2);

        submit_fact_to_store(&store, second_offer.clone()).expect("submit second offer");
        let third = drain_projection(&projector, &store, &[], None, 3)
            .expect("second offer wakes target with complete context");

        assert_eq!(third.projected, 2);
        let mut expected = first_offer.id.to_vec();
        expected.extend_from_slice(&second_offer.id);
        assert_eq!(
            intent_payload_for(&store, "multi_stage_ready", &target.id),
            expected
        );
        assert_eq!(pending_projection_count(&store, target.id), 0);
        assert!(stored_context_for_owner(&store, &target.id)
            .expect("target context")
            .needs
            .is_empty());
    }

    #[test]
    fn projection_drain_isolates_a_failed_fact_without_rolling_back_previous_items() {
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
        assert!(crate::core::store::persisted_fact(&store, &failing.id)
            .expect("load failing fact")
            .is_none());
    }

    #[test]
    fn projection_drain_keeps_a_context_inconsistent_fact_as_evidence() {
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

        assert_eq!(progress.projected, 2);
        assert_eq!(pending_projection_count(&store, offered.id), 0);

        // The failing fact authenticates (it parks when probed with empty
        // context), so the rejection was inconsistent *context*: it is kept as
        // evidence (bytes retained) and just not retried (pending cleared).
        assert_eq!(pending_projection_count(&store, failing.id), 0);
        assert!(crate::core::store::persisted_fact(&store, &failing.id)
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
        crate::core::project_fact::context_store::insert_context_offer_for_test(&store, &offer)
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
            .write_transaction(|tx| crate::core::store::insert_candidate_fact_in_tx(tx, &parent))
            .expect("insert candidate fact");

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
        assert!(crate::core::store::candidate_fact_by_id(&store, &parent.id)
            .expect("load ephemeral")
            .is_none());
        assert_eq!(
            crate::core::store::persisted_fact(&store, &child.id)
                .expect("load child")
                .as_ref(),
            Some(&child)
        );
        let child_context = stored_context_for_owner(&store, &child.id).expect("child context");
        assert_eq!(child_context.offers.len(), 1);
        assert!(child_context.needs.is_empty());
    }

    #[test]
    fn candidate_fact_missing_context_is_retained_and_parked() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let parent = Fact::new(FactScope::Local, 1, b"ephemeral-need".to_vec());
        store
            .write_transaction(|tx| crate::core::store::insert_candidate_fact_in_tx(tx, &parent))
            .expect("insert candidate fact");

        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([7; 32]);
        let projector = need_only(role.clone(), key.clone());
        let progress =
            drain_projection(&projector, &store, &[], None, 10).expect("candidate parks on needs");

        assert_eq!(progress.projected, 1);
        assert!(crate::core::store::candidate_fact_by_id(&store, &parent.id)
            .expect("load candidate")
            .is_none());
        assert!(crate::core::store::persisted_fact(&store, &parent.id)
            .expect("load retained candidate")
            .is_some());
        let context = stored_context_for_owner(&store, &parent.id).expect("parent context");
        assert_eq!(context.needs.len(), 1);
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
            .write_transaction(|tx| crate::core::store::insert_candidate_fact_in_tx(tx, &parent))
            .expect("insert candidate fact");

        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([8; 32]);
        let offer = ContextOffer {
            owner: offered.id,
            role: role.clone(),
            scope: parent.scope.clone(),
            start_key: key.clone(),
            end_key: key.clone(),
        };
        crate::core::project_fact::context_store::insert_context_offer_for_test(&store, &offer)
            .expect("insert stored offer");

        let projector = need_until_payload(role.clone(), key.clone(), "ephemeral_ready", None);
        let progress =
            drain_projection(&projector, &store, &[], None, 10).expect("drain projection");

        assert_eq!(progress.projected, 2);
        assert!(crate::core::store::candidate_fact_by_id(&store, &parent.id)
            .expect("load candidate")
            .is_none());
        assert!(crate::core::store::persisted_fact(&store, &parent.id)
            .expect("load retained candidate")
            .is_some());
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
            .write_transaction(|tx| crate::core::store::insert_candidate_fact_in_tx(tx, &parent))
            .expect("insert candidate fact");

        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([9; 32]);
        let projector = test_projector(move |fact, _context| {
            Ok(ProjectionOutput::new()
                .drop_candidate()
                .need(need_for(fact, &role, &key))
                .intent(Intent::new(
                    IntentKind::new("ephemeral_partial").unwrap(),
                    fact.id,
                    Vec::new(),
                )))
        });
        let err = drain_projection(&projector, &store, &[], None, 10)
            .expect_err("dropped candidates cannot partially succeed with unresolved probes");

        assert!(err.contains("transient needs remain"), "{err}");
        assert!(crate::core::store::candidate_fact_by_id(&store, &parent.id)
            .expect("load candidate")
            .is_some());
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
            .write_transaction(|tx| crate::core::store::insert_candidate_fact_in_tx(tx, &parent))
            .expect("insert candidate fact");

        let role = Role::new("ephemeral_offer").unwrap();
        let projector = test_projector(move |fact, _context| {
            let key = ContextKey::from_bytes(fact.id);
            Ok(ProjectionOutput::new()
                .drop_candidate()
                .offer(offer_for(fact, &role, &key)))
        });
        let err = drain_projection(&projector, &store, &[], None, 10)
            .expect_err("dropped candidate offers should fail");

        assert!(err.contains("dropped candidate fact cannot emit durable offers"));
        assert!(crate::core::store::candidate_fact_by_id(&store, &parent.id)
            .expect("load candidate")
            .is_some());
    }

    #[test]
    fn child_fact_parking_counts_as_successful_parent_projection() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("open store");
        let parent = Fact::new(FactScope::Local, 1, b"ephemeral-parent".to_vec());
        let child = Fact::new(FactScope::Global, 2, b"child-need".to_vec());
        store
            .write_transaction(|tx| crate::core::store::insert_candidate_fact_in_tx(tx, &parent))
            .expect("insert candidate fact");

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
        assert!(crate::core::store::candidate_fact_by_id(&store, &parent.id)
            .expect("load ephemeral")
            .is_none());
        assert!(crate::core::store::persisted_fact(&store, &child.id)
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
            .write_transaction(|tx| crate::core::store::insert_candidate_fact_in_tx(tx, &parent))
            .expect("insert candidate fact");

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
        assert!(crate::core::store::candidate_fact_by_id(&store, &parent.id)
            .expect("load ephemeral")
            .is_none());
        assert!(crate::core::store::persisted_fact(&store, &child.id)
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
    ) -> Result<crate::core::project_fact::ProjectionProgress, String> {
        crate::core::project_fact::drain_projection(
            store,
            projector,
            allowed_tables,
            fact_admission,
            limit,
        )
    }

    fn intent_payload_for(store: &Store, kind: &str, key: &FactId) -> Vec<u8> {
        intent_payload_for_maybe(store, kind, key).expect("load intent payload")
    }

    fn intent_payload_for_maybe(store: &Store, kind: &str, key: &FactId) -> Option<Vec<u8>> {
        store
            .conn()
            .query_row(
                "SELECT payload FROM intents WHERE kind = ?1 AND idempotence_key = ?2",
                rusqlite::params![kind, key.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .expect("load optional intent payload")
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

    fn pending_projection_match_count(store: &Store, owner: FactId) -> i64 {
        store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pending_projection_matches WHERE owner = ?1",
                rusqlite::params![owner.as_slice()],
                |row| row.get(0),
            )
            .expect("count pending projection matches")
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

    struct MultiStageDependencyProjector {
        target_id: FactId,
        first_offer_id: FactId,
        second_offer_id: FactId,
        first_role: Role,
        first_key: ContextKey,
        second_role: Role,
        second_key: ContextKey,
    }

    impl Projector for MultiStageDependencyProjector {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            if fact.id == self.first_offer_id {
                return Ok(ProjectionOutput::new().offer(offer_for(
                    fact,
                    &self.first_role,
                    &self.first_key,
                )));
            }
            if fact.id == self.second_offer_id {
                return Ok(ProjectionOutput::new().offer(offer_for(
                    fact,
                    &self.second_role,
                    &self.second_key,
                )));
            }
            if fact.id != self.target_id {
                return Ok(ProjectionOutput::new());
            }

            let first_need = need_for(fact, &self.first_role, &self.first_key);
            let Some(first_payload) = context.payload_for(&first_need) else {
                return Ok(ProjectionOutput::new().need(first_need));
            };
            let second_need = need_for(fact, &self.second_role, &self.second_key);
            let Some(second_payload) = context.payload_for(&second_need) else {
                return Ok(ProjectionOutput::new().need(first_need).need(second_need));
            };

            let mut payload = first_payload.id.to_vec();
            payload.extend_from_slice(&second_payload.id);
            Ok(ProjectionOutput::new().intent(Intent::new(
                IntentKind::new("multi_stage_ready").unwrap(),
                fact.id,
                payload,
            )))
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

// Core fact lifecycle and SQL-backed runtime projection.
//
// This module owns the reusable fact projection contract and queue worker.
// Core routes raw facts to protocol projectors:
//
// ```text
// route -> project -> effects/needs/offers -> commit
// ```
//
// Core owns queueing, matched context loading, need/offer parking, and commit
// boundaries. Protocol fact families own raw byte decoding, signature/context
// validation, legacy adaptation, semantic projection, row construction, and
// user-facing commands. Keeping the projector contract here lets core
// projection stay protocol-neutral without teaching it what a workspace, message,
// invite, key wrap, sync range, or connection fact means.
//
// The SQL-backed worker below owns one queued fact at a time: matched context
// loading, projector execution, candidate retention, context wake fanout,
// time-wake replacement, and projection effect commit.

/// Check a fact's content id against its own bytes.
///
/// Core constructs every `Fact` with `id = fact_id(bytes)`, so this normally
/// holds. Protocol-local validation helpers re-check it when they need a
/// self-contained proof over raw bytes.
pub fn verify_fact_id(fact: &crate::core::facts::Fact) -> Result<(), String> {
    if fact.id == crate::core::facts::fact_id(&fact.bytes) {
        Ok(())
    } else {
        Err("fact id does not match fact bytes".to_string())
    }
}
pub(crate) mod commit_effects {
    //! Atomic commit path for shared runtime effects.
    //!
    //! Core is built around a simple rule: runtime work describes what should
    //! change, then one commit boundary makes that description durable. Commands,
    //! projectors, and intent handlers do not directly mutate all of core state.
    //! They return `PipelineEffects`: facts to admit, facts to purge, row
    //! mutations, durable intents, and ephemeral intents. A commit is the
    //! moment those pending effects are validated, written to SQLite, and made
    //! visible together.
    //!
    //! Commit requests come from three places. `Runtime::submit_command_output`
    //! commits effects produced by a user-facing command. Fact projection owns a
    //! larger transaction that replaces that fact's needs and time wakes, appends
    //! offers, then calls the shared commit helper to write the projector's
    //! effects. Intent dispatch owns a larger transaction that deletes the handled
    //! queue row, then calls the same helper to write the handler's effects. Those
    //! callers own their surrounding pipeline work; this module owns the common
    //! effect language inside that work.
    //!
    //! Committing effects changes the runtime in four ways. Purged facts remove the
    //! fact and its core-owned derived rows. New facts enter `facts`,
    //! `local_fact_admissions`, and `pending_projection`. Row mutations update
    //! protocol or core IO tables the runtime explicitly allowed. Follow-up intents
    //! are recorded after the data they depend on, so later handler passes never see
    //! queued work for state that failed to commit.
    //!
    //! The mechanism is deliberately split in two. `validate_pipeline_effects`
    //! checks failures that do not need SQL: conflicting duplicate intents inside a
    //! batch and row mutations aimed at tables outside the runtime allowlist. The
    //! commit functions then rely on the store for the state-dependent checks:
    //! content-addressed facts must match their ids, opaque row-table `PutRow`
    //! effects must be new rows or exact duplicates, typed-table inserts must match
    //! the full supplied row, and intent queue inserts must keep `(kind, key)`
    //! stable.
    //!
    //! That row-table rule is not the rule for all projection state. Context rows
    //! and time wakes are handled by owner in the projection commit boundary before
    //! this helper commits shared effects: needs/time wakes are replaced, while
    //! durable offers append idempotently.
    //! Typed-table projections can also change visible state by emitting explicit
    //! `DeleteWhere` and `InsertValues` mutations in the desired order. The opaque
    //! `PutRow` path is narrower: it is for facts whose derived row key should
    //! continue to name the same bytes across retries and later context wakeups. If
    //! new context should change the value for an existing logical row, the protocol
    //! should model that as typed-table delete/insert state or choose a different
    //! row key, not rely on `PutRow` as an upsert.
    //!
    //! The commit order is part of the contract. Purges run first so stale
    //! core-owned rows disappear before new facts and derived rows become visible.
    //! New facts are admitted and marked pending for projection. Row mutations
    //! apply next. Follow-up durable and ephemeral intents are recorded last, so
    //! downstream work is not queued until the data it depends on has committed.
    //!
    //! Keep this file protocol-neutral. It may decide whether an effect is allowed
    //! to touch a registered table and whether an idempotent write conflicts with
    //! existing SQL state. It must not interpret payload bytes, decide which facts
    //! are valid, or know why a protocol table row matters. Add a new effect kind
    //! here only when it needs this same all-or-nothing commit boundary; display
    //! receipts, command-only output, and protocol policy belong in their owner
    //! modules.

    use crate::core::effects::PipelineEffects;
    use crate::core::intents::{
        Intent, RowMutation, TableDelete, TableDeleteWhere, TableInsert, Value as SqlValue,
    };
    use crate::core::schema::{INTENTS, LOCAL_INTENTS};
    use crate::core::store::{
        insert_candidate_fact_in_tx, insert_fact_and_pending_with_mode_in_tx, purge_fact_in_tx,
    };
    use crate::core::store::{
        quoted_identifier, quoted_identifier_list, quoted_table_name, Store, TableName, TableRow,
    };
    use rusqlite::{params_from_iter, OptionalExtension};
    use std::collections::BTreeMap;

    use super::context_store::insert_pending_matches_for_stored_needs_in_tx;
    use super::route::FactAdmissionFn;
    use super::ProjectionMode;
    use crate::core::handle_intent::record_intent_in_table_in_tx;

    /// Which follow-up intents may be recorded by this commit path.
    #[derive(Debug, Clone, Copy)]
    pub(crate) enum IntentAdmissionPolicy<'a> {
        /// Normal runtime behavior: record every emitted intent.
        All,
        /// Replay behavior: record only intents whose handlers are replay-allowed.
        AllowKinds(&'a [&'static str]),
    }

    impl IntentAdmissionPolicy<'_> {
        pub(crate) fn pending_projection_mode(self) -> ProjectionMode {
            match self {
                Self::All => ProjectionMode::Normal,
                Self::AllowKinds(_) => ProjectionMode::Replay,
            }
        }

        fn allows(self, intent: &Intent) -> bool {
            match self {
                Self::All => true,
                Self::AllowKinds(kinds) => kinds.contains(&intent.kind.as_str()),
            }
        }
    }

    /// Remove intents that are not admissible in the current runtime mode.
    pub(crate) fn suppress_disallowed_intents(
        effects: &mut PipelineEffects,
        policy: IntentAdmissionPolicy<'_>,
    ) -> usize {
        let durable_before = effects.intents.len();
        effects.intents.retain(|intent| policy.allows(intent));
        let local_before = effects.local_intents.len();
        effects.local_intents.retain(|intent| policy.allows(intent));
        (durable_before - effects.intents.len()) + (local_before - effects.local_intents.len())
    }

    /// Counts of newly inserted follow-up work after an effect commit.
    ///
    /// These counts are not a full change report. Purges, row mutations, and
    /// idempotent duplicates are intentionally omitted because callers use this as
    /// a scheduling signal for new facts and intents, not as an audit log.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub(crate) struct PipelineEffectCounts {
        /// Facts newly admitted.
        pub facts: usize,
        /// Durable intents newly queued.
        pub intents: usize,
        /// Ephemeral intents newly queued.
        pub local_intents: usize,
    }

    /// Validate the stateless parts of an effect batch before opening a transaction.
    ///
    /// This catches pure conflicts first, so callers fail with a useful error before
    /// any SQL writes are attempted. Existing-row conflicts are still checked at
    /// write time because they depend on the transaction's current view of SQLite.
    pub(crate) fn validate_pipeline_effects(
        effects: &PipelineEffects,
        allowed_tables: &[TableName],
    ) -> Result<(), String> {
        validate_intents(&effects.intents)?;
        validate_intents(&effects.local_intents)?;
        validate_row_mutations(&effects.row_mutations, allowed_tables)?;
        Ok(())
    }

    pub(crate) fn validate_pipeline_effects_for_admission(
        effects: &PipelineEffects,
        allowed_tables: &[TableName],
        fact_admission: Option<FactAdmissionFn>,
    ) -> Result<(), String> {
        validate_pipeline_effects(effects, allowed_tables)?;
        validate_fact_admissions(effects, fact_admission)?;
        Ok(())
    }

    fn validate_fact_admissions(
        effects: &PipelineEffects,
        fact_admission: Option<FactAdmissionFn>,
    ) -> Result<(), String> {
        let Some(fact_admission) = fact_admission else {
            return Ok(());
        };
        for fact in effects.facts.iter().chain(effects.candidate_facts.iter()) {
            fact_admission(fact)?;
        }
        Ok(())
    }

    /// Validate that a batch can be written to one intent queue.
    ///
    /// Intent durability is owned by the destination table. This check only rejects
    /// conflicting duplicates within that one destination queue; the durable and
    /// ephemeral queues are allowed to carry the same `(kind, key)` because
    /// dispatch defines how durable work shadows local work.
    fn validate_intents(intents: &[Intent]) -> Result<(), String> {
        let mut proposed = BTreeMap::<Vec<u8>, &Intent>::new();
        for intent in intents {
            let key = intent_validation_key(intent);
            if let Some(existing) = proposed.insert(key, intent) {
                if existing != intent {
                    return Err(format!(
                        "pipeline emitted conflicting intents for {}",
                        intent.kind.as_str()
                    ));
                }
            }
        }
        Ok(())
    }

    fn intent_validation_key(intent: &Intent) -> Vec<u8> {
        let mut key = intent.kind.as_str().as_bytes().to_vec();
        key.push(0);
        key.extend_from_slice(&intent.key);
        key
    }

    /// Reject any row mutation targeting a table this runtime has not registered.
    ///
    /// The allowlist is the ownership boundary between core and protocol storage.
    /// A row mutation can only name tables declared by the runtime description; the
    /// module that constructed the mutation still owns column meaning and payload
    /// validation.
    fn validate_row_mutations(
        mutations: &[RowMutation],
        allowed_tables: &[TableName],
    ) -> Result<(), String> {
        for mutation in mutations {
            validate_row_mutation_table(mutation, allowed_tables)?;
        }
        Ok(())
    }

    /// Split opaque row-table mutations into inserts and deletes for the store.
    ///
    /// Typed-table mutations stay in `row_mutations` because they need declared
    /// columns and predicates rather than the generic `row_key/row_value` shape.
    /// The split keeps the store's opaque-row API narrow while letting this file
    /// apply all row effects in one ordered commit pass.
    ///
    /// This also means opaque `PutRow` is not an update primitive. Inserts run
    /// before deletes, so a same-batch delete and put for the same key is not a
    /// replacement operation. Use typed-table mutations when projection needs
    /// explicit delete-then-insert state changes.
    fn row_mutation_rows(
        mutations: &[RowMutation],
        allowed_tables: &[TableName],
    ) -> Result<(Vec<TableRow>, Vec<TableDelete>), String> {
        let mut rows = Vec::new();
        let mut deletes = Vec::<TableDelete>::new();
        for mutation in mutations {
            validate_row_mutation_table(mutation, allowed_tables)?;
            match mutation {
                RowMutation::PutRow(row) => rows.push(row.clone()),
                RowMutation::DeleteRow(delete) => deletes.push(delete.clone()),
                RowMutation::InsertValues(_) | RowMutation::DeleteWhere(_) => {}
            }
        }
        Ok((rows, deletes))
    }

    fn validate_row_mutation_table(
        mutation: &RowMutation,
        allowed_tables: &[TableName],
    ) -> Result<(), String> {
        let table = match mutation {
            RowMutation::PutRow(row) => row.table,
            RowMutation::DeleteRow(delete) => delete.table,
            RowMutation::InsertValues(insert) => insert.table,
            RowMutation::DeleteWhere(delete) => delete.table,
        };
        if allowed_tables.contains(&table) {
            Ok(())
        } else {
            Err(format!(
                "row mutation table {} is not registered",
                table.as_str()
            ))
        }
    }

    /// Adapt a `String` error into the [`rusqlite::Error`] a transaction closure
    /// must return, so a non-SQL failure can still abort a commit.
    pub(crate) fn sqlite_string_error(err: String) -> rusqlite::Error {
        rusqlite::Error::InvalidParameterName(err)
    }

    /// Validate and commit effects in a new transaction owned by this helper.
    ///
    /// Use this for command submission and other callers that do not already have a
    /// larger atomic unit. Projection and intent dispatch usually call
    /// `commit_pipeline_effects_in_tx` instead so their own queue/context changes
    /// commit with the shared effects.
    pub(crate) fn commit_pipeline_effects_to_store(
        store: &Store,
        effects: &PipelineEffects,
        allowed_tables: &[TableName],
        fact_admission: Option<FactAdmissionFn>,
        label: &str,
    ) -> Result<PipelineEffectCounts, String> {
        validate_pipeline_effects_for_admission(effects, allowed_tables, fact_admission)?;
        store
            .write_transaction(|tx| {
                commit_pipeline_effects_in_tx(
                    tx,
                    effects,
                    allowed_tables,
                    fact_admission,
                    ProjectionMode::Normal,
                )
            })
            .map_err(|err| format!("{label}: {err}"))
    }

    /// Write all shared effects into an already-open transaction.
    ///
    /// The order is intentional: purges remove stale core-owned rows first, new
    /// facts become pending, rows mutate, and follow-up intents are recorded last.
    /// If any step fails, the caller's transaction rolls the whole batch back.
    ///
    /// This function does not open or close the transaction. The caller owns the
    /// larger atomic boundary, which is why projection can update context and time
    /// wakes before committing these effects, and dispatch can delete the handled
    /// intent row in the same SQL unit.
    pub(crate) fn commit_pipeline_effects_in_tx(
        tx: &Store,
        effects: &PipelineEffects,
        allowed_tables: &[TableName],
        fact_admission: Option<FactAdmissionFn>,
        pending_mode: ProjectionMode,
    ) -> rusqlite::Result<PipelineEffectCounts> {
        validate_fact_admissions(effects, fact_admission).map_err(sqlite_string_error)?;
        for purged in &effects.purged_facts {
            purge_fact_in_tx(tx, *purged)?;
        }

        let mut facts = 0usize;
        for fact in &effects.facts {
            if insert_fact_and_pending_with_mode_in_tx(tx, fact, pending_mode)? {
                insert_pending_matches_for_stored_needs_in_tx(tx, fact.id, pending_mode)
                    .map_err(sqlite_string_error)?;
                facts += 1;
            }
        }

        for fact in &effects.candidate_facts {
            insert_candidate_fact_in_tx(tx, fact)?;
        }

        let (rows, deletes) = row_mutation_rows(&effects.row_mutations, allowed_tables)
            .map_err(sqlite_string_error)?;
        tx.insert_table_rows_in_tx(rows)?;
        for delete in deletes {
            tx.delete_table_rows_in_tx(delete.table, vec![delete.key])?;
        }
        for mutation in &effects.row_mutations {
            match mutation {
                RowMutation::InsertValues(insert) => {
                    insert_values_in_tx(tx, insert)?;
                }
                RowMutation::DeleteWhere(delete) => {
                    delete_where_in_tx(tx, delete)?;
                }
                RowMutation::PutRow(_) | RowMutation::DeleteRow(_) => {}
            }
        }

        let mut intents = 0usize;
        for intent in &effects.intents {
            if record_intent_in_table_in_tx(tx, INTENTS, intent)? {
                intents += 1;
            }
        }

        let mut local_intents = 0usize;
        for intent in &effects.local_intents {
            if record_intent_in_table_in_tx(tx, LOCAL_INTENTS, intent)? {
                local_intents += 1;
            }
        }

        Ok(PipelineEffectCounts {
            facts,
            intents,
            local_intents,
        })
    }

    /// Insert a typed-table row idempotently.
    ///
    /// Unlike row tables, typed tables do not have a generic key/value shape. The
    /// complete supplied column set is therefore both the insert data and the
    /// idempotence check. If SQLite ignores the insert because a primary key or
    /// unique index already exists, the existing row must match every supplied
    /// column or the effect is rejected as a conflict.
    ///
    /// A typed table can still express changing projection state: emit a
    /// `DeleteWhere` for the old logical row before an `InsertValues` for the new
    /// row. The typed mutation loop preserves the order chosen by the protocol
    /// module.
    fn insert_values_in_tx(store: &Store, insert: &TableInsert) -> rusqlite::Result<usize> {
        validate_columns_and_values(insert.columns, &insert.values, "insert")?;
        let table = quoted_table_name(insert.table)?;
        let columns = quoted_identifier_list(insert.columns)?;
        let placeholders = placeholders(insert.values.len());
        let values = sqlite_values(&insert.values)?;
        let changed = store.conn().execute(
            &format!("INSERT OR IGNORE INTO {table} ({columns}) VALUES ({placeholders})"),
            params_from_iter(values.iter()),
        )?;
        if changed == 0 && !insert_values_match(store, insert, &values)? {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "conflicting row for {}",
                insert.table.as_str()
            )));
        }
        Ok(changed)
    }

    /// Check whether an ignored typed insert was an exact duplicate.
    ///
    /// This is intentionally stricter than "the key already exists": callers that
    /// emit typed rows must be able to retry the exact same effect without changing
    /// meaning, and must fail if the same database identity already names different
    /// column values.
    fn insert_values_match(
        store: &Store,
        insert: &TableInsert,
        values: &[rusqlite::types::Value],
    ) -> rusqlite::Result<bool> {
        let table = quoted_table_name(insert.table)?;
        let predicate = where_clause(insert.columns)?;
        store
            .conn()
            .query_row(
                &format!("SELECT 1 FROM {table} WHERE {predicate} LIMIT 1"),
                params_from_iter(values.iter()),
                |_| Ok(()),
            )
            .optional()
            .map(|row| row.is_some())
    }

    /// Delete typed-table rows by an exact column predicate.
    ///
    /// Deletes are idempotent absence requests. Deleting zero rows is successful
    /// because callers are asking the commit boundary to make matching rows absent,
    /// not asserting that a row must already exist.
    fn delete_where_in_tx(store: &Store, delete: &TableDeleteWhere) -> rusqlite::Result<usize> {
        validate_columns_and_values(delete.columns, &delete.values, "delete")?;
        let table = quoted_table_name(delete.table)?;
        let predicate = where_clause(delete.columns)?;
        let values = sqlite_values(&delete.values)?;
        store.conn().execute(
            &format!("DELETE FROM {table} WHERE {predicate}"),
            params_from_iter(values.iter()),
        )
    }

    fn validate_columns_and_values(
        columns: &[&str],
        values: &[SqlValue],
        label: &str,
    ) -> rusqlite::Result<()> {
        if columns.is_empty() {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "{label} mutation requires at least one column"
            )));
        }
        if columns.len() != values.len() {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "{label} mutation column/value count mismatch"
            )));
        }
        Ok(())
    }

    fn sqlite_values(values: &[SqlValue]) -> rusqlite::Result<Vec<rusqlite::types::Value>> {
        values.iter().map(SqlValue::as_sqlite_value).collect()
    }

    fn where_clause(columns: &[&str]) -> rusqlite::Result<String> {
        columns
            .iter()
            .enumerate()
            .map(|(index, column)| Ok(format!("{} = ?{}", quoted_identifier(column)?, index + 1)))
            .collect::<rusqlite::Result<Vec<_>>>()
            .map(|columns| columns.join(" AND "))
    }

    fn placeholders(count: usize) -> String {
        (1..=count)
            .map(|index| format!("?{index}"))
            .collect::<Vec<_>>()
            .join(", ")
    }
}
pub mod context {
    //! Projection context visible while processing one fact.

    use super::effects::{TimeRange, Timeline};
    use crate::core::context::{ContextNeed, ContextOffer};
    use crate::core::facts::Fact;
    use std::collections::BTreeMap;

    /// Runtime mode visible while projecting one fact.
    ///
    /// This is not fact-derived context. It is ambient execution state supplied by
    /// the queue item being processed: normal live projection or replay rebuild.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub enum ProjectionMode {
        /// Normal runtime projection.
        #[default]
        Normal,
        /// Replay rebuild projection.
        Replay,
    }

    impl ProjectionMode {
        pub(crate) const fn as_str(self) -> &'static str {
            match self {
                Self::Normal => "normal",
                Self::Replay => "replay",
            }
        }

        pub(crate) fn from_str(value: &str) -> Result<Self, String> {
            match value {
                "normal" => Ok(Self::Normal),
                "replay" => Ok(Self::Replay),
                other => Err(format!("unknown projection mode {other}")),
            }
        }

        pub fn is_replay(self) -> bool {
            matches!(self, Self::Replay)
        }
    }

    /// Matched context, mode, and due time ranges visible while projecting one fact.
    ///
    /// Core builds this immediately before calling the projector. It is a snapshot
    /// of matched rows for this run, not a live storage handle.
    #[derive(Debug, Clone, Default, PartialEq, Eq)]
    pub struct ProjectionContext {
        mode: ProjectionMode,
        offers: Vec<ContextOffer>,
        matched: Vec<MatchedContext>,
        matched_by_need: BTreeMap<ContextNeed, Vec<usize>>,
        time_ranges: Vec<TimeRange>,
    }

    /// One matched need/offer pair plus the offer owner's payload fact.
    ///
    /// Core constructs this from standing context rows before calling the
    /// projector. A projector may inspect the payload, but it must not assume core
    /// has validated the protocol semantics of that payload.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct MatchedContext {
        /// The need owned by the fact currently being projected.
        pub need: ContextNeed,
        /// The offer that satisfied the need.
        pub offer: ContextOffer,
        /// Payload fact loaded from the offer owner.
        pub payload: Fact,
    }

    impl ProjectionContext {
        /// Build context containing only unmatched standing offers.
        ///
        /// This shape is mainly used for facts with no needs; protocol code should
        /// prefer the matched-payload helpers when a proof depends on a need.
        pub fn new(offers: Vec<ContextOffer>) -> Self {
            Self {
                mode: ProjectionMode::Normal,
                offers,
                matched: Vec::new(),
                matched_by_need: BTreeMap::new(),
                time_ranges: Vec::new(),
            }
        }

        /// Build context from already matched need/offer/payload triples.
        pub fn from_matches(matched: Vec<MatchedContext>) -> Self {
            let mut offers = matched
                .iter()
                .map(|matched| matched.offer.clone())
                .collect::<Vec<_>>();
            offers.sort();
            offers.dedup();
            let matched_by_need = index_matches_by_need(&matched);
            Self {
                mode: ProjectionMode::Normal,
                offers,
                matched,
                matched_by_need,
                time_ranges: Vec::new(),
            }
        }

        /// Return whether this projection is a normal live run or a replay rebuild.
        pub fn mode(&self) -> ProjectionMode {
            self.mode
        }

        /// Return true when this projection is rebuilding from retained facts.
        pub fn is_replay(&self) -> bool {
            self.mode.is_replay()
        }

        /// Attach the runtime mode for this projection item.
        pub(crate) fn with_mode(mut self, mode: ProjectionMode) -> Self {
            self.mode = mode;
            self
        }

        /// Return all distinct offers visible to this projection run.
        pub fn offers(&self) -> &[ContextOffer] {
            &self.offers
        }

        /// Attach due time ranges selected by the daemon's time-wake pass.
        pub fn with_time_ranges(mut self, time_ranges: Vec<TimeRange>) -> Self {
            self.time_ranges = time_ranges;
            self
        }

        /// Return the largest due time in a range containing `at`.
        ///
        /// This is a context check, not a clock read. The daemon already decided
        /// which ranges were due and stored them for this projection pass.
        pub fn time_reached(&self, timeline: &Timeline, at: u64) -> Option<u64> {
            self.time_ranges
                .iter()
                .filter(|range| &range.timeline == timeline && range.contains(at))
                .map(|range| range.end_inclusive)
                .max()
        }

        /// Return the payload fact supplied for an exact need, if any.
        ///
        /// This is a lookup over context core already matched and loaded before
        /// projection. It does not query storage or run overlap queries.
        pub fn payload_for(&self, need: &ContextNeed) -> Option<&Fact> {
            self.matched_entries_for(need)
                .next()
                .map(|matched| &matched.payload)
        }

        pub fn payload_for_checked(
            &self,
            need: &ContextNeed,
            label: &str,
        ) -> Result<Option<&Fact>, String> {
            let Some(matched) = self.matched_entries_for(need).next() else {
                return Ok(None);
            };
            if matched.offer.owner != matched.payload.id {
                return Err(format!("{label} context offer payload mismatch"));
            }
            Ok(Some(&matched.payload))
        }

        /// Return every matched payload for a need, preserving its offer metadata.
        pub fn matched_payloads_for<'a>(
            &'a self,
            need: &'a ContextNeed,
        ) -> impl Iterator<Item = (&'a ContextOffer, &'a Fact)> + 'a {
            self.matched_entries_for(need)
                .map(|matched| (&matched.offer, &matched.payload))
        }

        fn matched_entries_for<'a>(
            &'a self,
            need: &ContextNeed,
        ) -> impl Iterator<Item = &'a MatchedContext> + 'a {
            self.matched_by_need
                .get(need)
                .into_iter()
                .flat_map(|indexes| indexes.iter().map(|index| &self.matched[*index]))
        }
    }

    fn index_matches_by_need(matched: &[MatchedContext]) -> BTreeMap<ContextNeed, Vec<usize>> {
        let mut matched_by_need = BTreeMap::<ContextNeed, Vec<usize>>::new();
        for (index, matched) in matched.iter().enumerate() {
            matched_by_need
                .entry(matched.need.clone())
                .or_default()
                .push(index);
        }
        matched_by_need
    }
}
pub(crate) mod context_store {
    //! Standing context rows, projection context assembly, and context wake fanout.
    //!
    //! Context is core's dependency surface between facts. A projector can say
    //! "this fact needs another fact with this role, scope, and byte range before it
    //! can finish" by emitting a `ContextNeed`, or "this fact provides payload for
    //! matching needs" by emitting a `ContextOffer`. Core does not know the
    //! protocol meaning of those relationships. It matches only stable role/scope
    //! partitions plus inclusive byte-range overlap.
    //!
    //! This module is where that model becomes SQL. The public vocabulary lives in
    //! `core::context`: needs, offers, roles, keys, scopes, and normalized
    //! `ContextSet`s. Protocol pipeline projectors produce those sets. The
    //! projection step calls this file to load previous standing context, assemble
    //! matched `ProjectionContext`, replace stored needs, append stored offers, and
    //! fan out wakeups to facts that may now make progress.
    //!
    //! The stored shape is one `context_edges` row per standing need or offer. The
    //! `owner` column is always the fact whose projection emitted the row. For
    //! offers, that same owner is also the payload fact loaded into matched
    //! projection context. Needs are current subscriptions: when a fact projects
    //! again, its new output replaces the old need rows it owned. Offers are
    //! append-only evidence: once inserted, an offer remains until the owner fact is
    //! purged.
    //!
    //! The invariant is replacement needs plus append-only offers. Projection
    //! output is the complete need set and new offer set for one fact, and wake
    //! fanout considers only added rows from the resulting delta. If protocol
    //! semantics change, keep the generic overlap query here and change the
    //! domain-owned key encoders/validators.

    use crate::core::context::{
        scope_key, ContextKey, ContextNeed, ContextOffer, ContextSet, ContextSetDelta, Role,
    };
    use crate::core::facts::{Fact, FactId, FactScope, ScopeKind};
    use crate::core::store::Store;
    use crate::core::store::{insert_pending_owner_with_mode_in_tx, persisted_fact};
    use crate::core::wire::{Reader, WireError};
    use rusqlite::params;
    use std::collections::{BTreeMap, BTreeSet};

    use super::{MatchedContext, ProjectionContext, ProjectionMode};

    const CONTEXT_NEED_DIRECTION: &str = "need";
    const CONTEXT_OFFER_DIRECTION: &str = "offer";

    /// Load a fact's standing context: the needs and offers it currently owns.
    pub(crate) fn stored_context_for_owner(
        store: &Store,
        owner: &FactId,
    ) -> Result<ContextSet, String> {
        Ok(ContextSet {
            needs: stored_needs_for_owner(store, owner)?,
            offers: stored_offers_for_owner(store, owner)?,
        }
        .normalized())
    }

    pub(crate) fn insert_context_need_in_tx(
        store: &Store,
        need: &ContextNeed,
    ) -> rusqlite::Result<bool> {
        insert_context_edge_in_tx(
            store,
            &need.owner,
            CONTEXT_NEED_DIRECTION,
            &need.role,
            &need.scope,
            need.start_key.as_bytes(),
            need.end_key.as_bytes(),
        )
    }

    /// Insert one standing offer row inside the projection transaction.
    pub(crate) fn insert_context_offer_in_tx(
        store: &Store,
        offer: &ContextOffer,
    ) -> rusqlite::Result<bool> {
        insert_context_edge_in_tx(
            store,
            &offer.owner,
            CONTEXT_OFFER_DIRECTION,
            &offer.role,
            &offer.scope,
            offer.start_key.as_bytes(),
            offer.end_key.as_bytes(),
        )
    }

    #[cfg(test)]
    pub(crate) fn insert_context_offer_for_test(
        store: &Store,
        offer: &ContextOffer,
    ) -> Result<(), String> {
        store
            .write_transaction(|tx| insert_context_offer_in_tx(tx, offer).map(|_| ()))
            .map_err(|err| format!("insert context offer: {err}"))
    }

    /// Load context offers whose range overlaps a single need range.
    pub(super) fn stored_overlapping_offers_for_need(
        store: &Store,
        need: &ContextNeed,
    ) -> Result<Vec<ContextOffer>, String> {
        let scope_key = scope_key(&need.scope);
        select_context_offers(
            store,
            r#"
        SELECT owner, role, scope_key, start_key, end_key
        FROM context_edges
        WHERE direction = 'offer'
          AND role = :role
          AND scope_key = :scope_key
          AND start_key <= :need_end
          AND end_key >= :need_start
        ORDER BY owner, start_key, end_key
        "#,
            &[
                (":role", text(need.role.as_str())),
                (":scope_key", bytes(&scope_key)),
                (":need_start", bytes(need.start_key.as_bytes())),
                (":need_end", bytes(need.end_key.as_bytes())),
            ],
        )
    }

    /// Load all needs owned by one fact.
    fn stored_needs_for_owner(store: &Store, owner: &FactId) -> Result<Vec<ContextNeed>, String> {
        select_context_needs(
            store,
            r#"
        SELECT owner, role, scope_key, start_key, end_key
        FROM context_edges
        WHERE owner = :owner
          AND direction = 'need'
        ORDER BY owner, role, scope_key, start_key, end_key
        "#,
            &[(":owner", bytes(owner))],
        )
    }

    /// Load all offers owned by one fact.
    fn stored_offers_for_owner(store: &Store, owner: &FactId) -> Result<Vec<ContextOffer>, String> {
        select_context_offers(
            store,
            r#"
        SELECT owner, role, scope_key, start_key, end_key
        FROM context_edges
        WHERE owner = :owner
          AND direction = 'offer'
        ORDER BY owner, role, scope_key, start_key, end_key
        "#,
            &[(":owner", bytes(owner))],
        )
    }

    fn select_context_needs(
        store: &Store,
        sql: &str,
        params: &[(&str, rusqlite::types::Value)],
    ) -> Result<Vec<ContextNeed>, String> {
        let mut stmt = store
            .conn()
            .prepare(sql)
            .map_err(|err| format!("load context needs: {err}"))?;
        bind_named_params(&mut stmt, params).map_err(|err| format!("load context needs: {err}"))?;
        let rows = stmt
            .raw_query()
            .mapped(selected_context_need)
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|err| format!("load context needs: {err}"))?;
        Ok(rows)
    }

    fn select_context_offers(
        store: &Store,
        sql: &str,
        params: &[(&str, rusqlite::types::Value)],
    ) -> Result<Vec<ContextOffer>, String> {
        let mut stmt = store
            .conn()
            .prepare(sql)
            .map_err(|err| format!("load context offers: {err}"))?;
        bind_named_params(&mut stmt, params)
            .map_err(|err| format!("load context offers: {err}"))?;
        let rows = stmt
            .raw_query()
            .mapped(selected_context_offer)
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|err| format!("load context offers: {err}"))?;
        Ok(rows)
    }

    fn insert_context_edge_in_tx(
        store: &Store,
        owner: &FactId,
        direction: &str,
        role: &Role,
        scope: &FactScope,
        start_key: &[u8],
        end_key: &[u8],
    ) -> rusqlite::Result<bool> {
        let scope_key = scope_key(scope);
        store
            .conn()
            .execute(
                "INSERT OR IGNORE INTO context_edges
                (owner, direction, role, scope_key, start_key, end_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    owner.as_slice(),
                    direction,
                    role.as_str(),
                    scope_key.as_slice(),
                    start_key,
                    end_key
                ],
            )
            .map(|count| count > 0)
    }

    /// Decode one persisted need row back into the public context type.
    fn selected_context_need(row: &rusqlite::Row<'_>) -> rusqlite::Result<ContextNeed> {
        Ok(ContextNeed {
            owner: fact_id_column(row.get::<_, Vec<u8>>(0)?, "owner")?,
            role: Role::new(row.get::<_, String>(1)?)
                .map_err(rusqlite::Error::InvalidParameterName)?,
            scope: decode_scope_key(&row.get::<_, Vec<u8>>(2)?)
                .map_err(rusqlite::Error::InvalidParameterName)?,
            start_key: ContextKey::from_bytes(row.get::<_, Vec<u8>>(3)?),
            end_key: ContextKey::from_bytes(row.get::<_, Vec<u8>>(4)?),
        })
    }

    /// Decode one persisted offer row back into the public context type.
    fn selected_context_offer(row: &rusqlite::Row<'_>) -> rusqlite::Result<ContextOffer> {
        Ok(ContextOffer {
            owner: fact_id_column(row.get::<_, Vec<u8>>(0)?, "owner")?,
            role: Role::new(row.get::<_, String>(1)?)
                .map_err(rusqlite::Error::InvalidParameterName)?,
            scope: decode_scope_key(&row.get::<_, Vec<u8>>(2)?)
                .map_err(rusqlite::Error::InvalidParameterName)?,
            start_key: ContextKey::from_bytes(row.get::<_, Vec<u8>>(3)?),
            end_key: ContextKey::from_bytes(row.get::<_, Vec<u8>>(4)?),
        })
    }

    fn bind_named_params(
        stmt: &mut rusqlite::Statement<'_>,
        params: &[(&str, rusqlite::types::Value)],
    ) -> rusqlite::Result<()> {
        for (name, value) in params {
            let index = stmt.parameter_index(name)?.ok_or_else(|| {
                rusqlite::Error::InvalidParameterName(format!(
                    "context SQL does not bind parameter {name}"
                ))
            })?;
            stmt.raw_bind_parameter(index, value)?;
        }
        Ok(())
    }

    fn fact_id_column(bytes: Vec<u8>, name: &str) -> rusqlite::Result<FactId> {
        bytes.try_into().map_err(|_| {
            rusqlite::Error::InvalidParameterName(format!(
                "context SQL column {name} is not a fact id"
            ))
        })
    }

    fn bytes(value: &[u8]) -> rusqlite::types::Value {
        rusqlite::types::Value::Blob(value.to_vec())
    }

    fn text(value: &str) -> rusqlite::types::Value {
        rusqlite::types::Value::Text(value.to_string())
    }

    fn decode_scope_key(bytes: &[u8]) -> Result<FactScope, String> {
        let mut reader = Reader::new(bytes);
        let scope = decode_scope(&mut reader)?;
        reader.finish().row()?;
        Ok(scope)
    }

    /// Decode the compact `scope_key` written by `context::scope_key`.
    fn decode_scope(reader: &mut Reader<'_>) -> Result<FactScope, String> {
        match reader.u8().row()? {
            0 => Ok(FactScope::Global),
            1 => Ok(FactScope::Local),
            2 => {
                let kind = ScopeKind::new(reader.string_u16be().row()?)?;
                let id = reader.array::<32>().row()?;
                Ok(FactScope::Scoped { kind, id })
            }
            other => Err(format!("invalid fact scope tag {other}")),
        }
    }

    trait RowWireResult<T> {
        fn row(self) -> Result<T, String>;
    }

    impl<T> RowWireResult<T> for Result<T, WireError> {
        fn row(self) -> Result<T, String> {
            self.map_err(|err| format!("invalid encoded row: {err}"))
        }
    }

    /// Load context matches already attached to one pending projection row.
    ///
    /// Context fanout records these rows when it queues the owner. Loading a
    /// pending item therefore does not have to search standing context for the
    /// owner's old needs before the first projector run.
    pub(crate) fn pending_matching_context_for_owner(
        store: &Store,
        owner: &FactId,
    ) -> Result<ProjectionContext, String> {
        let mut stmt = store
            .conn()
            .prepare(
                r#"
                SELECT need_role,
                       need_scope_key,
                       need_start_key,
                       need_end_key,
                       offer_owner,
                       offer_start_key,
                       offer_end_key
                FROM pending_projection_matches
                WHERE owner = ?1
                ORDER BY
                    need_role,
                    need_scope_key,
                    need_start_key,
                    need_end_key,
                    offer_owner,
                    offer_start_key,
                    offer_end_key
                "#,
            )
            .map_err(|err| format!("load pending projection matches: {err}"))?;
        let rows = stmt
            .query_map(params![owner.as_slice()], |row| {
                selected_pending_projection_match(row, owner)
            })
            .map_err(|err| format!("load pending projection matches: {err}"))?;
        let pairs = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|err| format!("load pending projection matches: {err}"))?;

        let mut matched = Vec::new();
        let mut seen = BTreeSet::new();
        let mut payloads = BTreeMap::new();
        for (need, offer) in pairs {
            push_stored_matched_context(
                store,
                &need,
                offer,
                &mut seen,
                &mut payloads,
                &mut matched,
            )?;
        }
        Ok(ProjectionContext::from_matches(matched))
    }

    fn selected_pending_projection_match(
        row: &rusqlite::Row<'_>,
        owner: &FactId,
    ) -> rusqlite::Result<(ContextNeed, ContextOffer)> {
        let role =
            Role::new(row.get::<_, String>(0)?).map_err(rusqlite::Error::InvalidParameterName)?;
        let scope = decode_scope_key(&row.get::<_, Vec<u8>>(1)?)
            .map_err(rusqlite::Error::InvalidParameterName)?;
        let need = ContextNeed {
            owner: *owner,
            role: role.clone(),
            scope: scope.clone(),
            start_key: ContextKey::from_bytes(row.get::<_, Vec<u8>>(2)?),
            end_key: ContextKey::from_bytes(row.get::<_, Vec<u8>>(3)?),
        };
        let offer = ContextOffer {
            owner: fact_id_column(row.get::<_, Vec<u8>>(4)?, "offer_owner")?,
            role,
            scope,
            start_key: ContextKey::from_bytes(row.get::<_, Vec<u8>>(5)?),
            end_key: ContextKey::from_bytes(row.get::<_, Vec<u8>>(6)?),
        };
        Ok((need, offer))
    }

    /// Add a matched pair and load the offer owner's payload fact.
    ///
    /// A missing payload is a storage invariant failure: context offers are only
    /// useful because their owner fact is the payload exposed to projection.
    fn push_stored_matched_context(
        store: &Store,
        need: &ContextNeed,
        offer: ContextOffer,
        seen: &mut BTreeSet<(ContextNeed, ContextOffer)>,
        payloads: &mut BTreeMap<FactId, Fact>,
        matched: &mut Vec<MatchedContext>,
    ) -> Result<(), String> {
        if !seen.insert((need.clone(), offer.clone())) {
            return Ok(());
        }
        let payload = if let Some(payload) = payloads.get(&offer.owner) {
            payload.clone()
        } else {
            let payload = persisted_fact(store, &offer.owner)?
                .ok_or_else(|| "context offer owner references unknown fact".to_string())?;
            payloads.insert(offer.owner, payload.clone());
            payload
        };
        matched.push(MatchedContext {
            need: need.clone(),
            offer,
            payload,
        });
        Ok(())
    }

    /// Insert pending owners woken by newly added context rows.
    ///
    /// Removals do not wake projection. A projector that stops needing context has
    /// already run; dependent facts wake only when a new need can now be satisfied
    /// or a new offer may satisfy existing needs.
    pub(crate) fn wake_context_matches_in_tx(
        store: &Store,
        delta: &ContextSetDelta,
        mode: ProjectionMode,
    ) -> Result<usize, String> {
        let mut changed = 0usize;
        for need in &delta.added_needs {
            for offer in stored_overlapping_offers_for_need(store, need)? {
                changed += insert_pending_projection_match_in_tx(store, need, &offer, mode)?;
            }
        }
        for offer in &delta.added_offers {
            for need in stored_overlapping_needs_for_offer(store, offer)? {
                changed += insert_pending_projection_match_in_tx(store, &need, offer, mode)?;
            }
        }
        Ok(changed)
    }

    /// Attach current stored matches for an owner that is being queued directly.
    ///
    /// Context wake fanout already knows the matching edge that caused the wake.
    /// Direct queueing paths, such as due time wakes or duplicate fact admission,
    /// use this helper to attach matches for any standing needs the owner already
    /// has.
    pub(super) fn insert_pending_matches_for_stored_needs_in_tx(
        store: &Store,
        owner: FactId,
        _mode: ProjectionMode,
    ) -> Result<usize, String> {
        record_pending_matches_for_stored_needs_in_tx(store, owner)
    }

    fn stored_overlapping_needs_for_offer(
        store: &Store,
        offer: &ContextOffer,
    ) -> Result<Vec<ContextNeed>, String> {
        let scope_key = scope_key(&offer.scope);
        select_context_needs(
            store,
            r#"
        SELECT n.owner, n.role, n.scope_key, n.start_key, n.end_key
        FROM context_edges n
        JOIN local_fact_admissions a ON a.fact_id = n.owner
        WHERE n.direction = 'need'
          AND n.role = :role
          AND n.scope_key = :scope_key
          AND n.start_key <= :offer_end
          AND n.end_key >= :offer_start
        ORDER BY a.received_at, n.owner, n.start_key, n.end_key
        "#,
            &[
                (":role", text(offer.role.as_str())),
                (":scope_key", bytes(&scope_key)),
                (":offer_start", bytes(offer.start_key.as_bytes())),
                (":offer_end", bytes(offer.end_key.as_bytes())),
            ],
        )
    }

    fn insert_pending_projection_match_in_tx(
        store: &Store,
        need: &ContextNeed,
        offer: &ContextOffer,
        mode: ProjectionMode,
    ) -> Result<usize, String> {
        if need.role != offer.role || need.scope != offer.scope {
            return Err("pending projection match role/scope mismatch".to_string());
        }
        let pending_changed = insert_pending_owner_with_mode_in_tx(store, need.owner, mode)
            .map_err(|err| format!("queue pending projection match: {err}"))?;
        let match_changed = record_pending_matches_for_stored_needs_in_tx(store, need.owner)?;
        Ok(usize::from(pending_changed > 0 || match_changed > 0))
    }

    fn record_pending_matches_for_stored_needs_in_tx(
        store: &Store,
        owner: FactId,
    ) -> Result<usize, String> {
        let mut changed = 0usize;
        for need in stored_needs_for_owner(store, &owner)? {
            for offer in stored_overlapping_offers_for_need(store, &need)? {
                changed += record_pending_projection_match_in_tx(store, &need, &offer)?;
            }
        }
        Ok(changed)
    }

    fn record_pending_projection_match_in_tx(
        store: &Store,
        need: &ContextNeed,
        offer: &ContextOffer,
    ) -> Result<usize, String> {
        if need.role != offer.role || need.scope != offer.scope {
            return Err("pending projection match role/scope mismatch".to_string());
        }
        let scope_key = scope_key(&need.scope);
        store
            .conn()
            .execute(
                "INSERT OR IGNORE INTO pending_projection_matches
                    (owner,
                     need_role,
                     need_scope_key,
                     need_start_key,
                     need_end_key,
                     offer_owner,
                     offer_start_key,
                     offer_end_key)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                params![
                    need.owner.as_slice(),
                    need.role.as_str(),
                    scope_key.as_slice(),
                    need.start_key.as_bytes(),
                    need.end_key.as_bytes(),
                    offer.owner.as_slice(),
                    offer.start_key.as_bytes(),
                    offer.end_key.as_bytes(),
                ],
            )
            .map_err(|err| format!("record pending projection match: {err}"))
    }
}
pub mod effects {
    //! Projection effects and time-wake output for fact pipeline stages.

    use crate::core::context::{ContextKey, ContextNeed, ContextOffer, ContextSet, Role};
    use crate::core::effects::PipelineEffects;
    use crate::core::facts::{Fact, FactId};
    use crate::core::intents::{Intent, RowMutation};

    const FACT_PURGED_ROLE: &str = "fact_purged";

    /// Context role used by deletion/retention projectors to wake a target fact.
    ///
    /// Core treats purge keys opaquely. Protocol families choose their own stable
    /// key shape and validate matched payloads before treating this context as
    /// authority. This context is proof and routing only. The target projector must
    /// still emit `ProjectionOutput::purge_self` after deleting its own rows so
    /// core removes the target fact bytes.
    pub fn fact_purged_role() -> Role {
        Role::expect(FACT_PURGED_ROLE)
    }

    pub fn fact_purged_need(
        owner: FactId,
        scope: crate::core::facts::FactScope,
        key: ContextKey,
    ) -> ContextNeed {
        ContextNeed {
            owner,
            role: fact_purged_role(),
            scope,
            start_key: key.clone(),
            end_key: key,
        }
    }

    pub fn fact_purged_offer(
        owner: FactId,
        scope: crate::core::facts::FactScope,
        key: ContextKey,
    ) -> ContextOffer {
        ContextOffer {
            owner,
            role: fact_purged_role(),
            scope,
            start_key: key.clone(),
            end_key: key,
        }
    }

    pub fn fact_purged_range_need(
        owner: FactId,
        scope: crate::core::facts::FactScope,
        start_key: ContextKey,
        end_key: ContextKey,
    ) -> ContextNeed {
        ContextNeed {
            owner,
            role: fact_purged_role(),
            scope,
            start_key,
            end_key,
        }
    }

    pub fn fact_purged_range_offer(
        owner: FactId,
        scope: crate::core::facts::FactScope,
        start_key: ContextKey,
        end_key: ContextKey,
    ) -> ContextOffer {
        ContextOffer {
            owner,
            role: fact_purged_role(),
            scope,
            start_key,
            end_key,
        }
    }

    /// Protocol-defined time-wake namespace.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Timeline(String);

    impl Timeline {
        /// Build a stable time-wake namespace.
        pub fn new(value: impl Into<String>) -> Result<Self, String> {
            let value = value.into();
            if value.is_empty() {
                return Err("timeline cannot be empty".to_string());
            }
            if !value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
            {
                return Err(format!("invalid timeline {value:?}"));
            }
            Ok(Self(value))
        }

        pub fn as_str(&self) -> &str {
            &self.0
        }
    }

    /// A scheduled wake owned by one fact.
    ///
    /// Projection output replaces all previous wakes for the owner. The daemon
    /// later turns due rows into pending projection plus `TimeRange` context.
    #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct TimeWake {
        /// Fact whose projection owns this wake.
        pub owner: FactId,
        /// Timeline namespace.
        pub timeline: Timeline,
        /// Inclusive scheduled time.
        pub at: u64,
    }

    /// A due time interval handed to a projector.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct TimeRange {
        /// Timeline namespace.
        pub timeline: Timeline,
        /// Lower bound already processed for this daemon admission, if any.
        pub start_exclusive: Option<u64>,
        /// Inclusive upper bound admitted for projection.
        pub end_inclusive: u64,
    }

    impl TimeRange {
        /// Return whether a scheduled point is inside this due interval.
        pub fn contains(&self, at: u64) -> bool {
            self.start_exclusive.is_none_or(|start| at > start) && at <= self.end_inclusive
        }
    }

    /// Complete uncommitted output of projecting one fact.
    ///
    /// `needs` and `time_wakes` are replacement sets owned by the projected fact.
    /// `offers` are append-only evidence owned by the projected fact. `effects` are
    /// ordinary runtime effects that commit in the same transaction after ownership
    /// checks pass.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct ProjectionOutput {
        /// Whether a candidate input should become a retained fact after successful
        /// projection. Durable facts are already retained, so this only affects
        /// `ProjectionSource::Candidate` items.
        pub retain_self: bool,
        /// Complete replacement needs for the projected fact.
        pub needs: Vec<ContextNeed>,
        /// New durable offers for the projected fact.
        pub offers: Vec<ContextOffer>,
        /// Complete replacement time wakes for the projected fact.
        pub time_wakes: Vec<TimeWake>,
        /// Child facts, self-purge, row mutations, and intents to commit with this projection.
        pub effects: PipelineEffects,
    }

    impl Default for ProjectionOutput {
        fn default() -> Self {
            Self {
                retain_self: true,
                needs: Vec::new(),
                offers: Vec::new(),
                time_wakes: Vec::new(),
                effects: PipelineEffects::default(),
            }
        }
    }

    impl ProjectionOutput {
        pub fn new() -> Self {
            Self::default()
        }

        /// Drop a volatile candidate after this projection instead of retaining it.
        ///
        /// This is for transport wrappers and other one-shot incoming facts. It has
        /// no effect on already retained facts.
        pub fn drop_candidate(mut self) -> Self {
            self.retain_self = false;
            self
        }

        pub fn need(mut self, need: ContextNeed) -> Self {
            self.needs.push(need);
            self
        }

        pub fn offer(mut self, offer: ContextOffer) -> Self {
            self.offers.push(offer);
            self
        }

        pub fn time_wake(mut self, wake: TimeWake) -> Self {
            self.time_wakes.push(wake);
            self
        }

        pub fn row_mutation(mut self, mutation: RowMutation) -> Self {
            self.effects.row_mutations.push(mutation);
            self
        }

        /// Purge the projected fact after its projector has removed owned rows.
        ///
        /// Core verifies at commit preparation that this id is the projected fact
        /// id. Cross-fact deletion must be expressed as context that wakes the
        /// target fact's projector, not as another projector purging it.
        pub fn purge_self(mut self, id: FactId) -> Self {
            self.effects.purged_facts.push(id);
            self
        }

        pub fn fact(mut self, fact: Fact) -> Self {
            self.effects.facts.push(fact);
            self
        }

        pub fn candidate_fact(mut self, fact: Fact) -> Self {
            self.effects.candidate_facts.push(fact);
            self
        }

        pub fn intent(mut self, intent: Intent) -> Self {
            self.effects.intents.push(intent);
            self
        }

        pub fn local_intent(mut self, intent: Intent) -> Self {
            self.effects.local_intents.push(intent);
            self
        }

        pub fn context_set(&self) -> ContextSet {
            ContextSet {
                needs: self.needs.clone(),
                offers: self.offers.clone(),
            }
            .normalized()
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::core::facts::FactScope;

        use super::*;

        #[test]
        fn purge_need_and_offer_match_same_opaque_key() {
            let scope = FactScope::Local;
            let key = ContextKey::from_bytes(vec![4, 2, 9]);
            let need = fact_purged_need([1; 32], scope.clone(), key.clone());
            let offer = fact_purged_offer([3; 32], scope.clone(), key);

            assert_eq!(need.role, offer.role);
            assert_eq!(need.scope, scope);
            assert_eq!(need.start_key, offer.start_key);
            assert_eq!(need.end_key, offer.end_key);
        }

        #[test]
        fn purge_range_need_spans_matching_offer_key() {
            let scope = FactScope::Local;
            let need = fact_purged_range_need(
                [1; 32],
                scope.clone(),
                ContextKey::from_bytes(vec![2, 0]),
                ContextKey::from_bytes(vec![2, 255]),
            );
            let offer =
                fact_purged_offer([3; 32], scope.clone(), ContextKey::from_bytes(vec![2, 9]));

            assert_eq!(need.role, offer.role);
            assert_eq!(need.scope, scope);
            assert!(need.start_key <= offer.start_key);
            assert!(need.end_key >= offer.end_key);
        }

        #[test]
        fn purge_range_offer_spans_matching_need_key() {
            let scope = FactScope::Local;
            let need = fact_purged_need([1; 32], scope.clone(), ContextKey::from_bytes(vec![2, 9]));
            let offer = fact_purged_range_offer(
                [3; 32],
                scope.clone(),
                ContextKey::from_bytes(vec![2, 0]),
                ContextKey::from_bytes(vec![2, 255]),
            );

            assert_eq!(need.role, offer.role);
            assert_eq!(need.scope, scope);
            assert!(offer.start_key <= need.start_key);
            assert!(offer.end_key >= need.end_key);
        }
    }
}
pub mod route {
    //! Fact route selection for read projection.

    use super::context::ProjectionContext;
    use super::effects::ProjectionOutput;
    use crate::core::facts::Fact;

    /// Function pointer used by static projector route tables.
    pub type ProjectorFn = fn(&Fact, &ProjectionContext) -> Result<ProjectionOutput, String>;
    /// Optional protocol-owned admission check for facts core is about to store.
    pub type FactAdmissionFn = fn(&Fact) -> Result<(), String>;
    /// Function that maps an envelope fact to its semantic fact tag.
    pub type EffectiveTagFn = fn(&Fact) -> Result<u8, String>;

    /// Human-readable projector declaration for a fact route.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FactPipeline {
        /// Projector implementation that owns this tag's local fact semantics.
        pub project: &'static str,
    }

    impl FactPipeline {
        pub const fn projector(project: &'static str) -> Self {
            Self { project }
        }
    }

    /// Route from a fact tag to the projector that owns that tag.
    #[derive(Debug, Clone, Copy)]
    pub struct FactRoute {
        /// Effective fact tag routed to this projector function.
        pub tag: u8,
        pub projector: ProjectorFn,
        /// Projector metadata for this route.
        pub pipeline: FactPipeline,
    }

    /// The protocol-facing projection entry point.
    pub trait Projector {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String>;
    }

    /// Route for envelope facts whose outer tag is not the semantic fact tag.
    #[derive(Debug, Clone, Copy)]
    pub struct EnvelopeRoute {
        /// Outer fact tag identifying the envelope layout.
        pub outer_tag: u8,
        /// Function that reads the envelope enough to choose the semantic route.
        pub effective_tag: EffectiveTagFn,
    }

    /// Tag router used by protocol registries.
    ///
    /// Core reads only the first byte and any protocol-supplied envelope tag
    /// function. It does not know what a tag means beyond selecting the registered
    /// projector function.
    #[derive(Debug, Clone, Copy)]
    pub struct RouterProjector {
        routes: &'static [FactRoute],
        envelopes: &'static [EnvelopeRoute],
    }

    impl RouterProjector {
        pub const fn new(
            routes: &'static [FactRoute],
            envelopes: &'static [EnvelopeRoute],
        ) -> Self {
            Self { routes, envelopes }
        }

        fn effective_tag(&self, fact: &Fact) -> Result<u8, String> {
            let Some(tag) = fact.bytes.first().copied() else {
                return Err("cannot project empty fact bytes".to_string());
            };
            if let Some(envelope) = self
                .envelopes
                .iter()
                .find(|envelope| envelope.outer_tag == tag)
            {
                return (envelope.effective_tag)(fact);
            }
            Ok(tag)
        }
    }

    impl Projector for RouterProjector {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            let tag = self.effective_tag(fact)?;
            let Some(route) = self.routes.iter().find(|route| route.tag == tag) else {
                return Err(format!("no target projector registered for fact tag {tag}"));
            };
            (route.projector)(fact, context)
        }
    }
}

pub use context::{MatchedContext, ProjectionContext, ProjectionMode};
pub use effects::{
    fact_purged_need, fact_purged_offer, fact_purged_range_need, fact_purged_range_offer,
    fact_purged_role, ProjectionOutput, TimeRange, TimeWake, Timeline,
};
pub use route::{
    EffectiveTagFn, EnvelopeRoute, FactAdmissionFn, FactPipeline, FactRoute, Projector,
    ProjectorFn, RouterProjector,
};

use crate::core::command_context::CommandOutput;
use crate::core::handle_intent::WorkStatus;
use crate::core::schema::{CANDIDATE_FACTS, PENDING_PROJECTION};
use crate::core::store::{
    candidate_pending_fact_ids, insert_fact_and_pending_in_tx, insert_pending_owner_with_mode_in_tx,
};

pub(crate) use commit_effects::IntentAdmissionPolicy;

/// Projection progress from one bounded drain pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ProjectionProgress {
    /// Number of facts that completed projection.
    pub(crate) projected: usize,
    /// Follow-up intents emitted by projection but suppressed by the current mode.
    pub(crate) suppressed_intents: usize,
    /// Whether the pass made progress or hit a retry.
    pub(crate) status: WorkStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingProjectionItem {
    fact_id: FactId,
    mode: ProjectionMode,
}

impl ProjectionProgress {
    /// Accumulate another projection progress report.
    fn merge(&mut self, other: Self) {
        self.projected += other.projected;
        self.suppressed_intents += other.suppressed_intents;
        self.status.merge(other.status);
    }
}

/// Count durable plus candidate facts currently queued for projection.
pub(crate) fn pending_fact_count(store: &Store) -> usize {
    store
        .table_row_count(PENDING_PROJECTION)
        .expect("pending projection count should load from store")
        + store
            .table_row_count(CANDIDATE_FACTS)
            .expect("candidate fact count should load from store")
}

/// Admit one fact after the runtime's protocol admission check.
pub(crate) fn submit_fact_with_admission(
    store: &Store,
    fact: Fact,
    fact_admission: Option<FactAdmissionFn>,
) -> Result<bool, String> {
    if let Some(admit) = fact_admission {
        admit(&fact)?;
    }
    submit_fact_to_store(store, fact)
}

/// Admit many facts after the runtime's protocol admission check.
pub(crate) fn submit_facts_with_admission(
    store: &Store,
    facts: impl IntoIterator<Item = Fact>,
    fact_admission: Option<FactAdmissionFn>,
) -> Result<usize, String> {
    let facts = facts.into_iter().collect::<Vec<_>>();
    if let Some(admit) = fact_admission {
        for fact in &facts {
            admit(fact)?;
        }
    }
    submit_facts_to_store(store, facts)
}

/// Commit command-authored facts and return the command receipt.
pub(crate) fn submit_command_output_to_store<T>(
    store: &Store,
    output: CommandOutput<T>,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    label: &str,
) -> Result<T, String> {
    let (receipt, facts) = output.into_parts();
    let mut effects = PipelineEffects::new();
    effects.facts = facts;
    commit_pipeline_effects_to_store(store, &effects, allowed_tables, fact_admission, label)?;
    Ok(receipt)
}

/// Drive one bounded projection drain pass.
pub(crate) fn drain_projection(
    store: &Store,
    projector: &(impl Projector + ?Sized),
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    limit: usize,
) -> Result<ProjectionProgress, String> {
    let mut total = ProjectionProgress::default();
    while total.projected < limit {
        let progress = drain_projection_once(
            store,
            projector,
            allowed_tables,
            fact_admission,
            limit - total.projected,
        )?;
        let projected = progress.projected > 0;
        total.merge(progress);
        if !projected {
            break;
        }
    }
    Ok(total)
}

fn drain_projection_once(
    store: &Store,
    projector: &(impl Projector + ?Sized),
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    limit: usize,
) -> Result<ProjectionProgress, String> {
    let mut progress = ProjectionProgress::default();

    let durable_items =
        crate::core::perf_profile::measure_result("projection_pending_load", || {
            pending_durable_projection_items(store, limit)
        })?;
    drain_projection_items(
        store,
        projector,
        ProjectionSource::Durable,
        durable_items,
        &mut progress,
        allowed_tables,
        fact_admission,
        limit,
    )?;

    if progress.projected < limit {
        let candidate_fact_ids =
            crate::core::perf_profile::measure_result("projection_candidate_load", || {
                candidate_pending_fact_ids(store, limit - progress.projected)
            })?;
        drain_projection_items(
            store,
            projector,
            ProjectionSource::Candidate,
            candidate_fact_ids
                .into_iter()
                .map(|fact_id| PendingProjectionItem {
                    fact_id,
                    mode: ProjectionMode::Normal,
                })
                .collect(),
            &mut progress,
            allowed_tables,
            fact_admission,
            limit,
        )?;
    }

    Ok(progress)
}

fn drain_projection_items(
    store: &Store,
    projector: &(impl Projector + ?Sized),
    source: ProjectionSource,
    items: Vec<PendingProjectionItem>,
    progress: &mut ProjectionProgress,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    limit: usize,
) -> Result<(), String> {
    for item in items {
        if progress.projected >= limit {
            break;
        }
        let fact_id = item.fact_id;
        let Some(pending_fact) =
            crate::core::perf_profile::measure_result("projection_load_pending_fact", || {
                load_pending_fact(store, source, fact_id, item.mode)
            })?
        else {
            purge_stale_projection_item(store, source, fact_id)?;
            continue;
        };
        let item = process_projection_item(
            store,
            projector,
            pending_fact,
            allowed_tables,
            fact_admission,
        )?;
        progress.suppressed_intents += item.suppressed_intents;
        if item.projected {
            progress.projected += 1;
            progress.status.progressed = true;
        }
    }
    Ok(())
}

/// Drain pending projection until no projection work remains or rounds expire.
pub(crate) fn process_projection_until_idle(
    store: &Store,
    projector: &(impl Projector + ?Sized),
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    max_rounds: usize,
    limit_per_round: usize,
) -> Result<WorkStatus, String> {
    let mut total = WorkStatus::idle();
    for _ in 0..max_rounds {
        let progress = drain_projection(
            store,
            projector,
            allowed_tables,
            fact_admission,
            limit_per_round,
        )?;
        total.merge(progress.status);
        if progress.projected == 0 && pending_fact_count(store) == 0 {
            return Ok(total);
        }
    }
    Err("projection work did not become idle within the round limit".to_string())
}

/// Turn due time wakes into pending projection work.
pub(crate) fn process_due_time_range(
    store: &Store,
    timeline: Timeline,
    start_exclusive: Option<u64>,
    end_inclusive: u64,
    limit: usize,
) -> Result<usize, String> {
    process_due_time_range_with_mode(
        store,
        timeline,
        start_exclusive,
        end_inclusive,
        limit,
        ProjectionMode::Normal,
    )
}

/// Turn replay due time wakes into replay projection work.
pub(crate) fn process_due_time_range_for_replay(
    store: &Store,
    timeline: Timeline,
    start_exclusive: Option<u64>,
    end_inclusive: u64,
    limit: usize,
) -> Result<usize, String> {
    process_due_time_range_with_mode(
        store,
        timeline,
        start_exclusive,
        end_inclusive,
        limit,
        ProjectionMode::Replay,
    )
}

/// Insert a fact and mark it pending in the same transaction.
pub(crate) fn submit_fact_to_store(store: &Store, fact: Fact) -> Result<bool, String> {
    let inserted = store
        .write_transaction(|tx| {
            let inserted = insert_fact_and_pending_in_tx(tx, &fact)?;
            if inserted {
                context_store::insert_pending_matches_for_stored_needs_in_tx(
                    tx,
                    fact.id,
                    ProjectionMode::Normal,
                )
                .map_err(commit_effects::sqlite_string_error)?;
            }
            Ok(inserted)
        })
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
            let mut inserted = 0;
            for fact in &facts {
                if insert_fact_and_pending_in_tx(tx, fact)? {
                    context_store::insert_pending_matches_for_stored_needs_in_tx(
                        tx,
                        fact.id,
                        ProjectionMode::Normal,
                    )
                    .map_err(commit_effects::sqlite_string_error)?;
                    inserted += 1;
                }
            }
            Ok(inserted)
        })
        .map_err(|err| format!("submit facts: {err}"))?;
    Ok(inserted)
}

/// Seed replay by queueing all retained facts as replay work.
pub(crate) fn enqueue_retained_facts_for_replay(store: &Store) -> Result<usize, String> {
    store
        .conn()
        .execute(
            "INSERT OR IGNORE INTO pending_projection (owner, mode)
             SELECT id, 'replay' FROM facts",
            [],
        )
        .map_err(|err| format!("enqueue retained facts for replay: {err}"))
}

/// Seed replay by queueing one retained fact as replay work.
pub(crate) fn enqueue_retained_fact_for_replay(
    store: &Store,
    fact_id: FactId,
) -> Result<bool, String> {
    store
        .conn()
        .execute(
            "INSERT OR IGNORE INTO pending_projection (owner, mode) VALUES (?1, 'replay')",
            params![fact_id.as_slice()],
        )
        .map(|inserted| inserted > 0)
        .map_err(|err| format!("enqueue retained fact for replay: {err}"))
}

/// Remove a fact and all core-owned durable rows keyed by its id.
///
/// Protocol-owned read-model rows are removed by projector row mutations or
/// protocol handlers, not by this generic core purge.
pub(crate) fn purge_fact_from_store(store: &Store, owner: FactId) -> Result<bool, String> {
    let changed = store
        .write_transaction(|tx| purge_fact_in_tx(tx, owner))
        .map_err(|err| format!("purge fact: {err}"))?;
    Ok(changed)
}

/// Turn due time wakes into pending projection work plus time context.
///
/// Time wakes are upstream of one-item projection. When a caller supplies a due
/// time window, matching owners are marked pending and receive that `TimeRange`
/// as projection context when `project_fact` later loads the item.
fn process_due_time_range_with_mode(
    store: &Store,
    timeline: Timeline,
    start_exclusive: Option<u64>,
    end_inclusive: u64,
    limit: usize,
    mode: ProjectionMode,
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
        .write_transaction(|tx| enqueue_due_time_wakes_in_tx(tx, &range, limit, mode))
        .map_err(|err| format!("process due time range: {err}"))
}

fn enqueue_due_time_wakes_in_tx(
    store: &Store,
    range: &TimeRange,
    limit: usize,
    mode: ProjectionMode,
) -> rusqlite::Result<usize> {
    let owners = due_time_wake_owners(store, range, limit)?;
    let has_start = range.start_exclusive.is_some();
    let has_start_i64 = i64::from(has_start);
    let start_exclusive = sqlite_u64(range.start_exclusive.unwrap_or(0), "start_exclusive")?;
    let end_inclusive = sqlite_u64(range.end_inclusive, "end_inclusive")?;

    let mut inserted = 0;
    for owner in owners {
        inserted += insert_pending_owner_with_mode_in_tx(store, owner, mode)?;
        context_store::insert_pending_matches_for_stored_needs_in_tx(store, owner, mode).map_err(
            |err| rusqlite::Error::InvalidParameterName(format!("queue time wake matches: {err}")),
        )?;
        store.conn().execute(
            "INSERT OR IGNORE INTO pending_time_ranges
                (owner, timeline, has_start, start_exclusive, end_inclusive)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                owner.as_slice(),
                range.timeline.as_str(),
                has_start_i64,
                start_exclusive,
                end_inclusive,
            ],
        )?;
    }

    Ok(inserted)
}

fn due_time_wake_owners(
    store: &Store,
    range: &TimeRange,
    limit: usize,
) -> rusqlite::Result<Vec<FactId>> {
    let has_start = range.start_exclusive.is_some();
    let has_start_i64 = i64::from(has_start);
    let start_exclusive = sqlite_u64(range.start_exclusive.unwrap_or(0), "start_exclusive")?;
    let end_inclusive = sqlite_u64(range.end_inclusive, "end_inclusive")?;
    let limit = i64::try_from(limit).map_err(|_| {
        rusqlite::Error::InvalidParameterName(
            "due time wake limit exceeds SQLite integer range".to_string(),
        )
    })?;
    let mut stmt = store.conn().prepare(
        r#"
        SELECT owner
        FROM time_wakes
        WHERE timeline = ?1
          AND (?2 = 0 OR at > ?3)
          AND at <= ?4
        ORDER BY at, owner
        LIMIT ?5
        "#,
    )?;
    let rows = stmt.query_map(
        params![
            range.timeline.as_str(),
            has_start_i64,
            start_exclusive,
            end_inclusive,
            limit,
        ],
        |row| fact_id_column(row.get::<_, Vec<u8>>(0)?, "owner"),
    )?;
    rows.collect()
}

/// Read the next durable pending fact ids without mutating the queue.
///
/// The item commit removes the row only after projection succeeds. Missing
/// facts are handled by the queue driver as stale pending rows.
fn pending_durable_projection_items(
    store: &Store,
    limit: usize,
) -> Result<Vec<PendingProjectionItem>, String> {
    let limit =
        i64::try_from(limit).map_err(|_| "pending projection limit exceeds i64".to_string())?;
    let mut stmt = store
        .conn()
        .prepare(
            r#"
            SELECT p.owner, p.mode
            FROM pending_projection p
            LEFT JOIN local_fact_admissions m ON m.fact_id = p.owner
            ORDER BY COALESCE(m.received_at, 9223372036854775807), p.owner
            LIMIT ?1
            "#,
        )
        .map_err(|err| format!("load pending projection: {err}"))?;
    let rows = stmt
        .query_map(params![limit], |row| {
            Ok(PendingProjectionItem {
                fact_id: fact_id_column(row.get::<_, Vec<u8>>(0)?, "owner")?,
                mode: projection_mode_column(row.get::<_, String>(1)?)?,
            })
        })
        .map_err(|err| format!("load pending projection: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("load pending projection: {err}"))
}

fn purge_stale_projection_item(
    store: &Store,
    source: ProjectionSource,
    fact_id: FactId,
) -> Result<(), String> {
    match source {
        ProjectionSource::Durable => purge_stale_durable_pending(store, fact_id),
        ProjectionSource::Candidate => drop_stale_candidate_fact(store, fact_id),
    }
}

fn drop_stale_candidate_fact(store: &Store, fact_id: FactId) -> Result<(), String> {
    store
        .write_transaction(|tx| delete_candidate_fact_in_tx(tx, fact_id))
        .map_err(|err| format!("purge stale candidate fact: {err}"))?;
    Ok(())
}

fn purge_stale_durable_pending(store: &Store, fact_id: FactId) -> Result<(), String> {
    store
        .write_transaction(|tx| purge_fact_in_tx(tx, fact_id))
        .map(|_| ())
        .map_err(|err| format!("purge stale durable pending fact: {err}"))
}

fn fact_id_column(bytes: Vec<u8>, name: &str) -> rusqlite::Result<FactId> {
    bytes.try_into().map_err(|_| {
        rusqlite::Error::InvalidParameterName(format!("{name} is not a 32-byte fact id"))
    })
}

fn projection_mode_column(value: String) -> rusqlite::Result<ProjectionMode> {
    ProjectionMode::from_str(&value).map_err(rusqlite::Error::InvalidParameterName)
}

fn sqlite_u64(value: u64, name: &str) -> rusqlite::Result<i64> {
    i64::try_from(value).map_err(|_| {
        rusqlite::Error::InvalidParameterName(format!(
            "{name}: SQL value exceeds SQLite integer range"
        ))
    })
}

pub(crate) use commit_effects::commit_pipeline_effects_to_store;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{ContextKey, ContextNeed, ContextOffer, Role};
    use crate::core::facts::{Fact, FactId, FactScope};
    use crate::core::handle_intent::{HandlerRoute, HandlerSet};
    use crate::core::intents::{HandlerContext, HandlerResult, Intent, IntentHandler};

    #[test]
    fn projection_output_keeps_context_and_work_separate() {
        let id = [1; 32];
        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([2; 32]);
        let output = ProjectionOutput::new()
            .need(ContextNeed {
                owner: id,
                role: role.clone(),
                scope: FactScope::Global,
                start_key: key.clone(),
                end_key: key.clone(),
            })
            .offer(ContextOffer {
                owner: id,
                role,
                scope: FactScope::Global,
                start_key: key.clone(),
                end_key: key,
            });

        assert_eq!(output.needs.len(), 1);
        assert_eq!(output.offers.len(), 1);
        assert!(output.effects.intents.is_empty());
    }

    #[test]
    fn projection_output_exposes_normalized_replacement_context() {
        let id = [1; 32];
        let role = Role::new("exact").unwrap();
        let need = ContextNeed {
            owner: id,
            role,
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([2; 32]),
            end_key: ContextKey::from_bytes([2; 32]),
        };
        let output = ProjectionOutput::new()
            .need(need.clone())
            .need(need.clone());

        assert_eq!(output.context_set().needs, vec![need]);
    }

    #[test]
    fn projection_context_returns_matched_payloads_by_need() {
        let role = Role::new("exact").unwrap();
        let need_a = ContextNeed {
            owner: [1; 32],
            role: role.clone(),
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([10; 32]),
            end_key: ContextKey::from_bytes([10; 32]),
        };
        let need_b = ContextNeed {
            owner: [2; 32],
            role: role.clone(),
            scope: FactScope::Global,
            start_key: ContextKey::from_bytes([20; 32]),
            end_key: ContextKey::from_bytes([20; 32]),
        };
        let context = ProjectionContext::from_matches(vec![
            matched_context(need_a.clone(), [11; 32]),
            matched_context(need_b.clone(), [22; 32]),
            matched_context(need_a.clone(), [33; 32]),
        ]);

        let payload_ids = context
            .matched_payloads_for(&need_a)
            .map(|(_offer, payload)| payload.id)
            .collect::<Vec<_>>();
        assert_eq!(payload_ids, vec![[11; 32], [33; 32]]);
        assert_eq!(
            context.payload_for(&need_b).map(|payload| payload.id),
            Some([22; 32])
        );
    }

    #[test]
    fn fact_route_records_projector_metadata() {
        fn model_projector(
            fact: &Fact,
            _context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            ModelProjector.project(fact, 15)
        }

        let route = FactRoute {
            tag: 200,
            projector: model_projector,
            pipeline: FactPipeline::projector("ModelProjector"),
        };

        assert_eq!(route.pipeline.project, "ModelProjector");
        let output = (route.projector)(
            &Fact::new(FactScope::Global, 1, vec![200, 5]),
            &ProjectionContext::default(),
        )
        .expect("route projection");
        assert_eq!(output.offers.len(), 1);
    }

    #[test]
    fn handler_sets_filter_command_and_replay_routes() {
        const ROUTES: &[HandlerRoute] = &[
            HandlerRoute {
                name: "semantic",
                intent_kind: "semantic",
                factory: noop_handler,
                runs_during_replay: true,
                recurrence: None,
            },
            HandlerRoute {
                name: "network",
                intent_kind: "network",
                factory: noop_handler,
                runs_during_replay: false,
                recurrence: None,
            },
        ];

        assert_eq!(
            HandlerSet::new(ROUTES).intent_kinds(),
            vec!["semantic", "network"]
        );
        assert_eq!(
            HandlerSet::new_excluding(ROUTES, &["network"]).intent_kinds(),
            vec!["semantic"]
        );
        assert_eq!(
            HandlerSet::new_replay(ROUTES).intent_kinds(),
            vec!["semantic"]
        );
    }

    struct ModelProjector;

    impl ModelProjector {
        fn project(&self, fact: &Fact, semantic: u16) -> Result<ProjectionOutput, String> {
            Ok(ProjectionOutput::new().offer(ContextOffer::range(
                fact.id,
                "model_semantic",
                FactScope::Global,
                vec![semantic as u8],
                vec![semantic as u8],
            )))
        }
    }

    struct NoopIntentHandler;

    impl IntentHandler for NoopIntentHandler {
        fn handle(&self, _intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
            Ok(crate::core::effects::PipelineEffects::new())
        }
    }

    fn noop_handler() -> Box<dyn IntentHandler> {
        Box::new(NoopIntentHandler)
    }

    fn matched_context(need: ContextNeed, payload_id: FactId) -> MatchedContext {
        let payload = Fact {
            id: payload_id,
            scope: need.scope.clone(),
            timestamp: 1,
            bytes: payload_id.to_vec(),
        };
        MatchedContext {
            offer: ContextOffer {
                owner: payload_id,
                role: need.role.clone(),
                scope: need.scope.clone(),
                start_key: need.start_key.clone(),
                end_key: need.end_key.clone(),
            },
            need,
            payload,
        }
    }
}
