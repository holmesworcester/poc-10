//! Projection queue storage and one-item projection commits.
//!
//! Projection is the only path from stored fact bytes to standing context,
//! materialized protocol rows, time wakes, purges, and follow-up work. The SQL
//! shape is intentionally small:
//!
//! - `facts` stores durable content-addressed fact bytes by id.
//! - `local_fact_admissions` stores the local metadata needed to interpret
//!   those bytes: scope, scope kind/id, and admission time. Loading a durable
//!   `Fact` always joins these two tables.
//! - `incoming_facts` is temp, process-local first-pass intake. Incoming rows
//!   project once; projection either moves them into durable `facts` plus
//!   `local_fact_admissions`, or drops them.
//! - `pending_projection` is the work queue keyed by fact id (`owner`) plus the
//!   time the owner entered the queue.
//! - `pending_projection_matches` and `pending_time_ranges` are pending input
//!   tables: they carry context matches and time ranges that woke an owner.
//!   They are consumed with the owner row.
//! - `context_needs` stores standing exact needs, `context_exact_offers` and
//!   `context_range_offers` store stamped scalar offers, and `time_wakes` stores
//!   standing future wake requests emitted by durable projection.
//!
//! SQL atomicity is the safety mechanism. Submitting a fact inserts bytes,
//! admission metadata, the pending row, and any already matched context in one
//! transaction. Staging an outside-origin incoming fact inserts a volatile
//! first-pass intake row. Projecting a queued fact then consumes that pending
//! work, replaces owned needs/time wakes, appends offers, compares the output
//! with current standing context, records newly woken owners, applies row
//! mutations, records intents, and moves/drops incoming rows in one transaction.
//! If SQLite rolls back, the old queue state remains. If it commits, the
//! projector output is visible as a complete unit.
//!
//! Projectors do not query the database for missing context during a run. Matched
//! offer values arrive through `ProjectionContext` because the pending row
//! already carries the offer id that woke it. Newly emitted needs may match
//! stored offers during commit, but those matches queue a later projection item.
//!
//! Queue recursion is explicit outside this item. If projection emits child
//! facts, shared effect commit stores them in `pending_projection`; if a later
//! item creates a matching offer, context fanout requeues the dependent owner.
//! Runtime later drains that work like any other queued fact.

use self::commit_effects::{
    commit_runtime_effects_in_tx, sqlite_string_error, storage_requirement_satisfied,
    validate_runtime_effects_for_admission,
};
use self::context_db::{
    delete_pending_matches_for_offer_owner_in_tx, pending_projection_input_context_for_owner,
    replace_context_for_owner_in_tx, wake_context_matches_in_tx,
};
#[cfg(test)]
use self::context_db::{
    insert_context_need_in_tx, insert_context_offer_in_tx, stored_context_for_owner,
};
use crate::core::command::AuthoredFacts;
use crate::core::context::{ContextSet, ContextSetAdditions};
use crate::core::db::{quoted_identifier, quoted_table_name, Db, TableName};
use crate::core::effects::RuntimeEffects;
use crate::core::facts::{
    fact_from_storage_row as validate_fact_query_result, fact_id, Fact, FactId,
};
use crate::core::perf_profile as perf;
use crate::core::schema::{
    CONTEXT_EXACT_OFFERS, CONTEXT_NEEDS, CONTEXT_RANGE_OFFERS, FACTS, INCOMING_FACTS,
    LOCAL_FACT_ADMISSIONS, PENDING_PROJECTION, PENDING_PROJECTION_MATCHES, PENDING_TIME_RANGES,
    TIME_WAKES,
};
use crate::core::wire::Writer;
use rusqlite::{params, OptionalExtension};

pub use crate::core::effects::IncomingMetadata;
pub use crate::core::facts::verify_fact_id;
pub(crate) use commit_effects::{
    commit_network_incoming_facts_to_db, commit_runtime_effects_to_db,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProjectionSource {
    /// Retained facts loaded from durable fact storage and local admission rows.
    Durable,
    /// Volatile process-local intake. Projection either retains or drops it.
    Incoming,
}

/// A loaded fact plus the already materialized inputs for this projection run.
pub(crate) struct ProjectionInput {
    source: ProjectionSource,
    fact: Fact,
    input_staged_at_ms: Option<u64>,
    pending_inputs: ProjectionContext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PendingProjectionItem {
    owner: FactId,
    mode: ProjectionMode,
}

enum ProjectionLoad {
    Stale {
        source: ProjectionSource,
        fact_id: FactId,
    },
    Loaded(ProjectionInput),
}

/// A projector result plus the projection-input metadata needed to commit it.
#[derive(Debug)]
struct PreparedProjection {
    source: ProjectionSource,
    fact: Fact,
    mode: ProjectionMode,
    input_received_at_ms: u64,
    input_staged_at_ms: Option<u64>,
    incoming_metadata: Option<IncomingMetadata>,
    retain_self: bool,
    projected_context: ContextSet,
    time_wakes: Vec<TimeWake>,
    runtime_effects: RuntimeEffects,
}

enum ProjectionOutcome {
    RetireStaleInput {
        source: ProjectionSource,
        fact_id: FactId,
    },
    RetireRejectedInput {
        source: ProjectionSource,
        fact_id: FactId,
    },
    Accepted(PreparedProjection),
}

#[derive(Clone, Copy)]
struct ProjectionEffectPolicy<'a, 'kind> {
    allowed_tables: &'a [TableName],
    registered_intent_kinds: &'a [&'kind str],
    fact_admission: Option<FactAdmissionFn>,
}

// =============================================================================
// Central Procedure
// =============================================================================

/// Project one fact-like input selected from one source.
///
/// Run and commit one queued projection item.
///
/// Runtime owns source order and batching; this function owns the complete work
/// unit after the caller has selected a source.
///
/// This is the whole projection worker in miniature:
///
/// 1. Load one projection input from SQL.
/// 2. Evaluate the projector against that in-memory input.
/// 3. Commit the terminal outcome in one SQL transaction.
///
/// Everything below this function exists to keep those three stages precise.
/// Load owns queue selection and context/time input materialization. Evaluate
/// owns pure projector execution and output validation. Commit owns every SQL
/// mutation, including stale cleanup, rejected-input retirement, current-context
/// comparison, and wake fanout.
pub(crate) fn project_one(
    store: &Db,
    projector: &(impl Projector + ?Sized),
    source: ProjectionSource,
    allowed_tables: &[TableName],
    registered_intent_kinds: &[&str],
    fact_admission: Option<FactAdmissionFn>,
) -> Result<bool, String> {
    let effect_policy = ProjectionEffectPolicy {
        allowed_tables,
        registered_intent_kinds,
        fact_admission,
    };
    let load = match load_one_projection_input(store, source)? {
        None => return Ok(false),
        Some(load) => load,
    };

    let outcome = match load {
        ProjectionLoad::Loaded(input) => {
            evaluate_loaded_projection_input(projector, input, effect_policy)?
        }
        ProjectionLoad::Stale { source, fact_id } => {
            // The selected queue/intake owner no longer has backing bytes, so
            // there is no fact to evaluate. Commit still owns retiring that
            // stale owner from SQL.
            ProjectionOutcome::RetireStaleInput { source, fact_id }
        }
    };

    commit_projection_effects(store, &outcome, effect_policy)?;
    Ok(true)
}

// =============================================================================
// Stages
// =============================================================================

/// Stage 1: load one projection input.
///
/// Durable projection drains from `pending_projection`; incoming projection
/// drains directly from volatile `incoming_facts`. This stage reads only: it
/// returns no work, a loaded fact plus pending inputs, or a stale selected owner
/// whose backing bytes disappeared before load.
fn load_one_projection_input(
    store: &Db,
    source: ProjectionSource,
) -> Result<Option<ProjectionLoad>, String> {
    let Some(item) =
        perf::measure_result("projection_queue_load", || source.next_pending_owner(store))?
    else {
        return Ok(None);
    };

    let Some(input) = perf::measure_result("projection_load_pending_fact", || {
        load_pending_fact(store, source, item.owner, item.mode)
    })?
    else {
        return Ok(Some(ProjectionLoad::Stale {
            source,
            fact_id: item.owner,
        }));
    };

    Ok(Some(ProjectionLoad::Loaded(input)))
}

/// Load the selected fact and the non-fact inputs for one projection run.
///
/// The selected owner came from either durable `pending_projection` or volatile
/// `incoming_facts`. Returning `None` means that selected work is stale: the
/// queue/intake row still existed, but the backing fact bytes were gone by the
/// time load reached them. Otherwise this assembles the exact in-memory shape
/// passed to the projector: the `Fact`, optional source-local timing metadata,
/// and `ProjectionContext`.
///
/// `pending_inputs` means "inputs pending for this projection item." For durable
/// facts those are recorded context matches and due time ranges that woke or
/// requeued the owner. For incoming first-pass facts there are no standing
/// context matches yet; the context only carries incoming origin metadata.
pub(crate) fn load_pending_fact(
    store: &Db,
    source: ProjectionSource,
    fact_id: FactId,
    mode: ProjectionMode,
) -> Result<Option<ProjectionInput>, String> {
    let fact = perf::measure_result("projection_load_fact", || source.load_fact(store, fact_id))?;
    let Some(fact) = fact else {
        return Ok(None);
    };
    let input_staged_at_ms = source.input_staged_at(store, fact_id)?;
    let pending_inputs = source.load_pending_inputs(store, fact_id, mode)?;
    Ok(Some(ProjectionInput {
        source,
        fact,
        input_staged_at_ms,
        pending_inputs,
    }))
}

/// Stage 2: run the protocol projector and validate its uncommitted output.
///
/// This stage is pure with respect to SQL. It never clears a queue row, deletes
/// incoming intake, publishes context, or commits runtime effects. It does use
/// `ProjectionEffectPolicy` to validate projector-emitted row mutations,
/// follow-up intents, and facts before accepting the outcome.
fn evaluate_loaded_projection_input(
    projector: &(impl Projector + ?Sized),
    input: ProjectionInput,
    effect_policy: ProjectionEffectPolicy<'_, '_>,
) -> Result<ProjectionOutcome, String> {
    let source = input.source;
    let fact_id = input.fact.id;
    let projection = match perf::measure_result("projection_prepare_effects", || {
        prepare_projection(projector, input, effect_policy)
    }) {
        Ok(projection) => projection,
        Err(_rejection) => {
            return Ok(ProjectionOutcome::RetireRejectedInput { source, fact_id });
        }
    };
    Ok(ProjectionOutcome::Accepted(projection))
}

/// Stage 3: commit one projection outcome as a single SQL transaction.
///
/// Commit owns every SQL mutation after selection. Stale inputs are cleaned,
/// rejected inputs are retired, and accepted projector output becomes visible:
/// source queue/intake rows are consumed, standing projection state is replaced,
/// newly visible context wakes dependent facts, and runtime effects are admitted
/// last.
///
/// Accepted commits are written as substages inside the transaction so the
/// projection loop is visible here: settle this input's lifecycle, publish
/// retained owner state, wake projection work from new context, then commit
/// projector-emitted effects.
///
/// This is the commit_projection_effects work item named in the architecture
/// contract tests.
fn commit_projection_effects(
    store: &Db,
    outcome: &ProjectionOutcome,
    effect_policy: ProjectionEffectPolicy<'_, '_>,
) -> Result<(), String> {
    perf::measure_result("projection_commit_effects", || {
        store
            .write_transaction(|tx| {
                perf::measure_result("projection_commit_tx_body", || match outcome {
                    ProjectionOutcome::RetireStaleInput { source, fact_id } => {
                        commit_stale_projection_input_in_tx(tx, *source, *fact_id)
                    }
                    ProjectionOutcome::RetireRejectedInput { source, fact_id } => {
                        commit_rejected_projection_input_in_tx(tx, *source, *fact_id)
                    }
                    ProjectionOutcome::Accepted(projection) => {
                        let fact_id = projection.fact.id;
                        if !storage_requirement_satisfied(
                            tx,
                            projection.runtime_effects.storage_requirement,
                        )
                        .map_err(sqlite_string_error)?
                        {
                            return commit_rejected_projection_input_in_tx(
                                tx,
                                projection.source,
                                fact_id,
                            );
                        }

                        let retained =
                            commit_accepted_input_lifecycle_in_tx(tx, projection, fact_id)?;
                        record_projection_timing_in_tx(tx, projection, retained)?;
                        let new_context = publish_retained_projection_state_in_tx(
                            tx, projection, fact_id, retained,
                        )?;
                        wake_projection_work_from_new_context_in_tx(tx, &new_context)?;
                        commit_projector_emitted_runtime_effects_in_tx(
                            tx,
                            projection,
                            effect_policy,
                        )
                    }
                })
            })
            .map_err(|err| format!("commit projection effects: {err}"))
    })
}

// =============================================================================
// Load Stage Helpers
// =============================================================================

impl ProjectionSource {
    /// Select the next owner for this source without mutating source state.
    ///
    /// Durable projection is driven by `pending_projection`; incoming projection
    /// is driven directly by first-pass `incoming_facts`. The later commit stage
    /// is responsible for consuming or retiring the selected row.
    fn next_pending_owner(self, store: &Db) -> Result<Option<PendingProjectionItem>, String> {
        match self {
            ProjectionSource::Durable => next_durable_projection_item(store),
            ProjectionSource::Incoming => next_incoming_projection_item(store),
        }
    }

    /// Load the fact bytes plus the local admission columns needed to build `Fact`.
    ///
    /// Durable rows split content identity from admission metadata:
    /// `facts` owns content-addressed bytes, while `local_fact_admissions`
    /// owns local scope and receive time. Incoming rows are self-contained
    /// because they have not yet been retained into durable fact storage.
    fn load_fact(self, store: &Db, fact_id: FactId) -> Result<Option<Fact>, String> {
        match self {
            ProjectionSource::Durable => store
                .conn()
                .query_row(
                    "SELECT f.id, m.scope, m.scope_kind, m.scope_id, m.received_at, f.bytes
                     FROM facts f
                     JOIN local_fact_admissions m ON m.fact_id = f.id
                     WHERE f.id = ?1
                     LIMIT 1",
                    params![fact_id.as_slice()],
                    validate_fact_query_result,
                )
                .optional()
                .map_err(|err| format!("load durable projection fact: {err}")),
            ProjectionSource::Incoming => store
                .conn()
                .query_row(
                    "SELECT id, scope, scope_kind, scope_id, received_at, bytes
                     FROM incoming_facts
                     WHERE id = ?1
                     LIMIT 1",
                    params![fact_id.as_slice()],
                    validate_fact_query_result,
                )
                .optional()
                .map_err(|err| format!("load incoming projection fact: {err}")),
        }
    }

    /// Return when this source first staged the input, when that fact is known.
    ///
    /// Durable facts may be requeued many times and do not have a single current
    /// staging moment. Incoming rows do, so timing diagnostics can distinguish
    /// intake latency from later projection latency.
    fn input_staged_at(self, store: &Db, fact_id: FactId) -> Result<Option<u64>, String> {
        match self {
            ProjectionSource::Durable => Ok(None),
            ProjectionSource::Incoming => store
                .conn()
                .query_row(
                    "SELECT staged_at
                     FROM incoming_facts
                     WHERE id = ?1
                     LIMIT 1",
                    params![fact_id.as_slice()],
                    |row| {
                        let staged_at = row.get::<_, i64>(0)?;
                        u64_column(staged_at, "incoming fact staged_at")
                    },
                )
                .optional()
                .map_err(|err| format!("load incoming projection staged_at: {err}")),
        }
    }

    /// Build the `ProjectionContext` visible to this projection run.
    ///
    /// Durable pending inputs are the matched context offer values and due time
    /// ranges recorded when the owner was queued. Incoming first-pass inputs do
    /// not participate in standing context yet, so the context only carries the
    /// execution mode and optional origin metadata supplied by intake.
    fn load_pending_inputs(
        self,
        store: &Db,
        fact_id: FactId,
        mode: ProjectionMode,
    ) -> Result<ProjectionContext, String> {
        match self {
            ProjectionSource::Durable => {
                let time_ranges =
                    perf::measure_result("projection_load_pending_time_inputs", || {
                        pending_time_ranges_for_owner(store, fact_id)
                    })?;
                let context =
                    perf::measure_result("projection_load_pending_context_inputs", || {
                        pending_projection_input_context_for_owner(store, &fact_id)
                    })?
                    .with_time_ranges(time_ranges)
                    .with_mode(mode);
                Ok(context)
            }
            ProjectionSource::Incoming => {
                let mut context = ProjectionContext::default().with_mode(mode);
                if let Some(metadata) = incoming_origin_metadata_by_id(store, &fact_id)
                    .map_err(|err| format!("load incoming metadata: {err}"))?
                {
                    context = context.with_incoming_metadata(metadata);
                }
                Ok(context)
            }
        }
    }
}

/// Read the oldest durable pending fact id without mutating the queue.
///
/// The item commit removes the row only after projection succeeds. Missing
/// facts are handled by the queue driver as stale pending rows.
fn next_durable_projection_item(store: &Db) -> Result<Option<PendingProjectionItem>, String> {
    store
        .conn()
        .query_row(
            r#"
            SELECT owner, replay
            FROM pending_projection
            ORDER BY priority, queued_at, owner
            LIMIT 1
            "#,
            [],
            |row| {
                Ok(PendingProjectionItem {
                    owner: fact_id_column(row.get::<_, Vec<u8>>(0)?, "owner")?,
                    mode: projection_mode_from_replay_flag(row.get(1)?),
                })
            },
        )
        .optional()
        .map_err(|err| format!("load pending projection: {err}"))
}

/// Read the oldest incoming first-pass fact id without mutating intake.
///
/// Incoming rows have not projected yet, so every row is runnable. If first-pass
/// projection needs context and retains the fact, the commit moves it into
/// durable fact storage where later wakeups use `pending_projection`.
fn next_incoming_projection_item(store: &Db) -> Result<Option<PendingProjectionItem>, String> {
    store
        .conn()
        .query_row(
            r#"
            SELECT id
            FROM incoming_facts
            ORDER BY received_at, id
            LIMIT 1
            "#,
            [],
            |row| {
                Ok(PendingProjectionItem {
                    owner: fact_id_column(row.get::<_, Vec<u8>>(0)?, "incoming id")?,
                    mode: ProjectionMode::Normal,
                })
            },
        )
        .optional()
        .map_err(|err| format!("load incoming facts: {err}"))
}

/// Decode the replay bit stored on durable pending projection rows.
fn projection_mode_from_replay_flag(replay: i64) -> ProjectionMode {
    if replay == 0 {
        ProjectionMode::Normal
    } else {
        ProjectionMode::Replay
    }
}

// =============================================================================
// Project Stage Helpers
// =============================================================================

/// Call the protocol projector and normalize the output for SQL commit.
///
/// Projection output replaces current needs and appends durable offers for this
/// fact. This helper enforces that projectors only own their own context/time
/// rows and may purge only their own fact. Standing-context comparison happens
/// later inside the commit transaction.
fn prepare_projection(
    projector: &(impl Projector + ?Sized),
    input: ProjectionInput,
    effect_policy: ProjectionEffectPolicy<'_, '_>,
) -> Result<PreparedProjection, String> {
    let ProjectionInput {
        source,
        fact,
        input_staged_at_ms,
        pending_inputs,
    } = input;
    let mode = pending_inputs.mode();
    let input_received_at_ms = fact.timestamp;
    let incoming_metadata = pending_inputs.incoming_metadata().cloned();
    let output = perf::measure_result("projection_projector_cpu", || {
        projector.project(&fact, &pending_inputs)
    })?;
    enforce_owner_is_self(&fact, &output)?;
    let projected_context = projected_context_with_offer_values(&output, &fact);
    let runtime_effects = output.effects;
    validate_rebuild_projection_shape(&projected_context, &output.time_wakes, &runtime_effects)?;
    perf::measure_result("projection_validate_effects", || {
        validate_runtime_effects_for_admission(
            &runtime_effects,
            effect_policy.allowed_tables,
            effect_policy.registered_intent_kinds,
            effect_policy.fact_admission,
        )
    })?;
    Ok(PreparedProjection {
        source,
        fact,
        mode,
        input_received_at_ms,
        input_staged_at_ms,
        incoming_metadata,
        retain_self: output.retain_self,
        projected_context,
        time_wakes: output.time_wakes,
        runtime_effects,
    })
}

fn projected_context_with_offer_values(output: &ProjectionOutput, fact: &Fact) -> ContextSet {
    let mut context = output.context_set();
    for offer in &mut context.offers {
        if offer.value.is_empty() {
            offer.value = fact.bytes.clone();
        }
    }
    context
}

fn validate_rebuild_projection_shape(
    context: &ContextSet,
    time_wakes: &[TimeWake],
    effects: &RuntimeEffects,
) -> Result<(), String> {
    if !effects.rebuild_derived_state {
        return Ok(());
    }
    if !context.needs.is_empty() || !context.offers.is_empty() || !time_wakes.is_empty() {
        return Err(
            "derived-state rebuild projection cannot publish standing context or time wakes"
                .to_string(),
        );
    }
    Ok(())
}

/// Reject any projected need, offer, time wake, or purge whose owner is not the
/// fact being projected.
fn enforce_owner_is_self(fact: &Fact, output: &ProjectionOutput) -> Result<(), String> {
    for purged in &output.effects.purged_facts {
        enforce_projected_owner("projector tried to purge fact", *purged, fact.id)?;
    }
    for need in &output.needs {
        enforce_projected_owner("projector emitted need with owner", need.owner, fact.id)?;
    }
    for offer in &output.offers {
        enforce_projected_owner("projector emitted offer with owner", offer.owner, fact.id)?;
    }
    for wake in &output.time_wakes {
        enforce_projected_owner(
            "projector emitted time wake with owner",
            wake.owner,
            fact.id,
        )?;
    }
    Ok(())
}

fn enforce_projected_owner(label: &str, owner: FactId, fact_id: FactId) -> Result<(), String> {
    if owner == fact_id {
        Ok(())
    } else {
        Err(format!(
            "{label} {:x?} that is not the projected fact {:x?}",
            owner, fact_id
        ))
    }
}

// =============================================================================
// Commit Stage Helpers
// =============================================================================

/// Retire selected work whose backing bytes disappeared between selection and load.
///
/// Durable stale rows are purged as corrupt owner-scoped state. Incoming stale
/// rows are just deleted from volatile intake.
fn commit_stale_projection_input_in_tx(
    tx: &Db,
    source: ProjectionSource,
    fact_id: FactId,
) -> rusqlite::Result<()> {
    match source {
        ProjectionSource::Durable => purge_fact_in_tx(tx, fact_id).map(|_| ()),
        ProjectionSource::Incoming => delete_incoming_fact_in_tx(tx, fact_id).map(|_| ()),
    }
}

/// Retire selected work rejected by pure projector evaluation.
///
/// Durable bytes stay retained as evidence; only pending work markers are cleared.
/// Incoming rows are volatile and are dropped on rejection.
fn commit_rejected_projection_input_in_tx(
    tx: &Db,
    source: ProjectionSource,
    fact_id: FactId,
) -> rusqlite::Result<()> {
    match source {
        ProjectionSource::Durable => clear_pending_projection_work_in_tx(tx, fact_id),
        ProjectionSource::Incoming => delete_incoming_fact_in_tx(tx, fact_id).map(|_| ()),
    }
}

fn projection_retains_fact_after_commit(projection: &PreparedProjection) -> bool {
    let fact_id = projection.fact.id;
    let purges_self = projection.runtime_effects.purged_facts.contains(&fact_id);
    match projection.source {
        ProjectionSource::Durable => !purges_self,
        ProjectionSource::Incoming => projection.retain_self && !purges_self,
    }
}

/// Commit the accepted input's queue/intake lifecycle.
///
/// Durable inputs clear pending work. Incoming inputs are volatile: projection
/// either retains them as ordinary facts or drops them. The returned boolean is
/// whether this fact remains retained and may publish standing context/time rows.
fn commit_accepted_input_lifecycle_in_tx(
    tx: &Db,
    projection: &PreparedProjection,
    fact_id: FactId,
) -> rusqlite::Result<bool> {
    let retained = projection_retains_fact_after_commit(projection);
    match projection.source {
        ProjectionSource::Durable => perf::measure_result("projection_clear_pending_work", || {
            clear_pending_projection_work_in_tx(tx, fact_id)
        })?,
        ProjectionSource::Incoming if retained => {
            // Retention is the only path from volatile intake to durable fact
            // storage. `move_incoming_to_retained_in_tx` also clears transient
            // owner rows before the retained projection state is written below.
            move_incoming_to_retained_in_tx(tx, &projection.fact).map(|_| ())?
        }
        ProjectionSource::Incoming => {
            // A dropped incoming row is allowed to produce effects only when it
            // has no unresolved transient needs and leaves no durable projection
            // state behind.
            validate_dropped_incoming_projection(projection).map_err(sqlite_string_error)?;
            perf::measure_result("projection_delete_incoming_fact", || {
                delete_incoming_fact_in_tx(tx, fact_id).map(|_| ())
            })?
        }
    };
    Ok(retained)
}

/// Record local timing for a successful projection commit.
///
/// `origin_received_at` is copied from volatile incoming metadata when present.
/// If a fact parks from incoming into durable storage before its final useful
/// projection, later durable projections keep the first origin receive time.
fn record_projection_timing_in_tx(
    tx: &Db,
    projection: &PreparedProjection,
    retained: bool,
) -> rusqlite::Result<()> {
    if !projection_timing_enabled() {
        return Ok(());
    }
    let source = match projection.source {
        ProjectionSource::Durable => "durable",
        ProjectionSource::Incoming => "incoming",
    };
    let received_at = sqlite_u64(
        projection.input_received_at_ms,
        "projection input received_at",
    )?;
    let origin_received_at = projection
        .incoming_metadata
        .as_ref()
        .map(|metadata| {
            sqlite_u64(
                metadata.received_at_local_ms,
                "projection origin received_at",
            )
        })
        .transpose()?;
    let input_staged_at = projection
        .input_staged_at_ms
        .map(|staged_at| sqlite_u64(staged_at, "projection input staged_at"))
        .transpose()?;
    let retained = if retained { 1i64 } else { 0i64 };
    let projected_at = queue_now_ms()?;
    let fact_type = projection
        .fact
        .body()
        .first()
        .map(|value| *value as i64)
        .unwrap_or(-1);
    tx.conn().execute(
        "INSERT INTO projection_timings
            (
                fact_id,
                fact_type,
                source,
                received_at,
                origin_received_at,
                input_staged_at,
                first_projected_at,
                projected_at,
                projection_count,
                retained
            )
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 1, ?8)
         ON CONFLICT(fact_id) DO UPDATE SET
            fact_type = excluded.fact_type,
            source = excluded.source,
            received_at = excluded.received_at,
            origin_received_at = COALESCE(
                excluded.origin_received_at,
                projection_timings.origin_received_at
            ),
            input_staged_at = COALESCE(
                excluded.input_staged_at,
                projection_timings.input_staged_at
            ),
            first_projected_at = projection_timings.first_projected_at,
            projected_at = excluded.projected_at,
            projection_count = projection_timings.projection_count + 1,
            retained = excluded.retained",
        params![
            projection.fact.id.as_slice(),
            fact_type,
            source,
            received_at,
            origin_received_at,
            input_staged_at,
            projected_at,
            retained,
        ],
    )?;
    Ok(())
}

#[cfg(test)]
fn projection_timing_enabled() -> bool {
    true
}

#[cfg(not(test))]
fn projection_timing_enabled() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("TOPO_PROFILE_PROJECTION_TIMING")
            .ok()
            .map(|value| {
                let normalized = value.trim().to_ascii_lowercase();
                !(normalized.is_empty() || normalized == "0" || normalized == "false")
            })
            .unwrap_or(false)
    })
}

/// Publish standing owner state for a retained projection.
///
/// Incoming facts that are not retained are volatile one-shot inputs, so they
/// cannot leave context or time wake rows behind.
fn publish_retained_projection_state_in_tx(
    tx: &Db,
    projection: &PreparedProjection,
    fact_id: FactId,
    retained: bool,
) -> rusqlite::Result<ContextSetAdditions> {
    let context_additions =
        replace_needs_and_append_offers_if_retained_in_tx(tx, projection, fact_id, retained)?;
    replace_time_wakes_if_retained_in_tx(tx, projection, fact_id, retained)?;
    Ok(context_additions)
}

/// Replace retained needs and append retained offers.
///
/// The returned additions are computed inside the commit transaction against the
/// current context edge view. Only those new relationships can wake other
/// projection work.
fn replace_needs_and_append_offers_if_retained_in_tx(
    tx: &Db,
    projection: &PreparedProjection,
    fact_id: FactId,
    retained: bool,
) -> rusqlite::Result<ContextSetAdditions> {
    if !retained {
        return Ok(ContextSetAdditions::default());
    }
    perf::measure_result("projection_replace_context", || {
        debug_assert_eq!(projection.fact.id, fact_id);
        replace_context_for_owner_in_tx(tx, &projection.fact, &projection.projected_context)
    })
}

/// Replace retained time wakes. Time wakes do not participate in context wake fanout.
fn replace_time_wakes_if_retained_in_tx(
    tx: &Db,
    projection: &PreparedProjection,
    fact_id: FactId,
    retained: bool,
) -> rusqlite::Result<()> {
    if !retained {
        return Ok(());
    }
    perf::measure_result("projection_replace_time_wakes", || {
        replace_stored_time_wake_owner_rows(tx, fact_id, &projection.time_wakes)
    })
}

/// Queue facts unblocked by the context this projection just made visible.
fn wake_projection_work_from_new_context_in_tx(
    tx: &Db,
    context_additions: &ContextSetAdditions,
) -> rusqlite::Result<()> {
    perf::measure_result("projection_wake_context_matches", || {
        wake_context_matches_in_tx(tx, &context_additions).map_err(sqlite_string_error)
    })
    .map(|_| ())
}

/// Commit projector-emitted facts, purges, rows, and intents after owner state.
fn commit_projector_emitted_runtime_effects_in_tx(
    tx: &Db,
    projection: &PreparedProjection,
    effect_policy: ProjectionEffectPolicy<'_, '_>,
) -> rusqlite::Result<()> {
    perf::measure_result("projection_commit_runtime_effects", || {
        commit_runtime_effects_in_tx(
            tx,
            &projection.runtime_effects,
            effect_policy.allowed_tables,
            effect_policy.registered_intent_kinds,
            effect_policy.fact_admission,
            projection.mode.is_replay(),
            true,
        )
    })
    .map(|_| ())
}

fn validate_dropped_incoming_projection(projection: &PreparedProjection) -> Result<(), String> {
    // A dropped incoming fact is a one-shot input: it cannot leave standing
    // projection state behind. Runtime effects are allowed only after all
    // transient needs are resolved; otherwise core would commit effects from a
    // projection that explicitly said it still lacked context.
    if !projection.projected_context.offers.is_empty() {
        return Err("dropped incoming fact cannot emit durable offers".to_string());
    }
    if !projection.time_wakes.is_empty() {
        return Err("dropped incoming fact cannot emit time wakes".to_string());
    }
    if !projection.projected_context.needs.is_empty() && !projection.runtime_effects.is_empty() {
        return Err(
            "dropped incoming fact cannot emit effects while transient needs remain".to_string(),
        );
    }
    Ok(())
}

fn clear_pending_projection_work_in_tx(store: &Db, owner: FactId) -> rusqlite::Result<()> {
    for table in [
        PENDING_PROJECTION,
        PENDING_PROJECTION_MATCHES,
        PENDING_TIME_RANGES,
    ] {
        delete_rows_by_owner_in_tx(store, table, owner)?;
    }
    Ok(())
}

fn delete_rows_by_owner_in_tx(
    store: &Db,
    table: TableName,
    owner: FactId,
) -> rusqlite::Result<usize> {
    let table = quoted_table_name(table)?;
    store.conn().execute(
        &format!("DELETE FROM {table} WHERE owner = ?1"),
        params![owner.as_slice()],
    )
}

/// Replace all time wakes owned by this fact.
///
/// Time wakes are not appended: projection output is the complete current
/// schedule for the owner, so old rows must disappear when the projection no
/// longer emits them.
fn replace_stored_time_wake_owner_rows(
    store: &Db,
    owner: FactId,
    wakes: &[TimeWake],
) -> rusqlite::Result<()> {
    delete_rows_by_owner_in_tx(store, TIME_WAKES, owner)?;
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

pub(crate) mod commit_effects {
    //! Atomic commit path for shared runtime effects.
    //!
    //! Core is built around a simple rule: runtime work describes what should
    //! change, then one commit boundary makes that description durable. Commands,
    //! projectors, and intent handlers do not directly mutate all of core state.
    //! They return `RuntimeEffects`: facts to admit, priority facts to project
    //! before ordinary work, facts to purge, row mutations, durable intents, and
    //! ephemeral intents. A commit is the moment those pending effects are
    //! validated, written to SQLite, and made visible together.
    //!
    //! Commit requests come from three places. `Runtime::submit_authored_facts`
    //! commits effects produced by a user-facing command. Fact projection owns a
    //! larger transaction that replaces that fact's needs and time wakes, appends
    //! offers, then calls the shared commit helper to write the projector's
    //! effects. Intent dispatch owns a larger transaction that deletes the handled
    //! queue row, then calls the same helper to write the handler's effects. Those
    //! callers own their surrounding runtime work; this module owns the common
    //! effect language inside that work.
    //!
    //! Committing effects changes the runtime in five ways. Purged facts remove
    //! the fact and its core-owned derived rows. A rebuild request clears
    //! resettable derived state and marks retained facts pending in replay mode.
    //! New facts enter `facts`, `local_fact_admissions`, and
    //! `pending_projection`; priority facts use the same storage path but sort
    //! before ordinary projection work. Row mutations update protocol or core IO
    //! tables the runtime explicitly allowed. Follow-up intents are recorded
    //! after the data they depend on, so later handler passes never see queued
    //! work for state that failed to commit.
    //!
    //! The mechanism is deliberately split in two. `validate_runtime_effects`
    //! checks failures that do not need SQL: unknown intent kinds, invalid
    //! rebuild batches, and row mutations aimed at tables outside the runtime
    //! allowlist. The commit functions then rely on the database for the
    //! state-dependent checks: content-addressed facts must match their ids and
    //! typed-table inserts must be new rows or exact duplicates of the full
    //! supplied row.
    //!
    //! That row-table rule is not the rule for all projection state. Context rows
    //! and time wakes are handled by owner in the projection commit boundary before
    //! this helper commits shared effects: needs/time wakes are replaced, while
    //! durable offers append idempotently.
    //! Typed-table projections can change visible state by emitting explicit
    //! `DeleteWhere` and `InsertValues` mutations in the desired order.
    //!
    //! The commit order is part of the contract. Purges run first so stale
    //! core-owned rows disappear before new facts and derived rows become
    //! visible. A rebuild wipe runs before fact admission and row mutations; that
    //! lets a control-plane projector request rebuild and then write the version
    //! or marker row that survives it. New facts are admitted and marked pending
    //! for projection. Row mutations apply next. Follow-up durable and ephemeral
    //! intents are recorded last, so downstream work is not queued until the data
    //! it depends on has committed.
    //!
    //! Keep this file protocol-neutral. It may decide whether an effect is allowed
    //! to touch a registered table and whether a typed-table write conflicts with
    //! existing SQL state. It must not interpret payload bytes, decide which facts
    //! are valid, or know why a protocol table row matters. Add a new effect kind
    //! here only when it needs this same all-or-nothing commit boundary; display
    //! receipts, command-only output, and protocol policy belong in their owner
    //! modules.

    use super::context::ProjectionMode;
    use super::route::FactAdmissionFn;
    use super::{
        insert_facts_and_record_matches_with_mode_in_tx, insert_incoming_fact_with_metadata_in_tx,
        insert_priority_facts_and_record_matches_with_mode_in_tx, purge_fact_in_tx,
    };
    use crate::core::db::{Db, TableName};
    use crate::core::effects::{IncomingMetadata, RuntimeEffects, StorageRequirement};
    use crate::core::facts::Fact;
    use crate::core::intents::{Intent, RowMutation};

    /// Counts of follow-up work recorded after an effect commit.
    ///
    /// These counts are not a full change report. Purges, row mutations, and
    /// exact duplicate facts are intentionally omitted because callers use this
    /// as a scheduling signal for new facts and intents, not as an audit log.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub(crate) struct RuntimeEffectCounts {
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
    pub(crate) fn validate_runtime_effects(
        effects: &RuntimeEffects,
        allowed_tables: &[TableName],
        registered_intent_kinds: &[&str],
    ) -> Result<(), String> {
        validate_intents(&effects.intents, registered_intent_kinds)?;
        validate_intents(&effects.local_intents, registered_intent_kinds)?;
        validate_incoming_fact_metadata(effects)?;
        validate_rebuild_effect_shape(effects)?;
        validate_row_mutations(&effects.row_mutations, allowed_tables)?;
        Ok(())
    }

    pub(crate) fn validate_runtime_effects_for_admission(
        effects: &RuntimeEffects,
        allowed_tables: &[TableName],
        registered_intent_kinds: &[&str],
        fact_admission: Option<FactAdmissionFn>,
    ) -> Result<(), String> {
        validate_runtime_effects(effects, allowed_tables, registered_intent_kinds)?;
        validate_fact_admissions(effects, fact_admission)?;
        Ok(())
    }

    fn validate_fact_admissions(
        effects: &RuntimeEffects,
        fact_admission: Option<FactAdmissionFn>,
    ) -> Result<(), String> {
        let Some(fact_admission) = fact_admission else {
            return Ok(());
        };
        effects
            .facts
            .iter()
            .chain(effects.priority_facts.iter())
            .chain(effects.incoming_facts.iter())
            .try_for_each(fact_admission)
    }

    fn validate_rebuild_effect_shape(effects: &RuntimeEffects) -> Result<(), String> {
        if !effects.rebuild_derived_state {
            return Ok(());
        }
        if !effects.facts.is_empty()
            || !effects.priority_facts.is_empty()
            || !effects.incoming_facts.is_empty()
            || !effects.intents.is_empty()
            || !effects.local_intents.is_empty()
        {
            return Err(
                "derived-state rebuild effect cannot be mixed with facts or intents".to_string(),
            );
        }
        Ok(())
    }

    fn validate_incoming_fact_metadata(effects: &RuntimeEffects) -> Result<(), String> {
        for fact_id in effects.incoming_fact_metadata.keys() {
            if !effects
                .incoming_facts
                .iter()
                .any(|fact| &fact.id == fact_id)
            {
                return Err(
                    "incoming fact metadata must reference an emitted incoming fact".to_string(),
                );
            }
        }
        Ok(())
    }

    /// Validate that a batch can be written to one intent queue.
    ///
    /// Intent durability is owned by the destination table. Core only validates
    /// that every emitted kind has a handler in this runtime; repeated keys are
    /// distinct queued rows.
    fn validate_intents(
        intents: &[Intent],
        registered_intent_kinds: &[&str],
    ) -> Result<(), String> {
        for intent in intents {
            crate::core::handle_intent::validate_intent_kind_registered(
                intent,
                registered_intent_kinds,
            )?;
        }
        Ok(())
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
        mutations.iter().try_for_each(|mutation| {
            let table = match mutation {
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
        })
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
    /// `commit_runtime_effects_in_tx` instead so their own queue/context changes
    /// commit with the shared effects.
    pub(crate) fn commit_runtime_effects_to_db(
        store: &Db,
        effects: &RuntimeEffects,
        allowed_tables: &[TableName],
        registered_intent_kinds: &[&str],
        fact_admission: Option<FactAdmissionFn>,
        replay: bool,
        allow_rebuild: bool,
        label: &str,
    ) -> Result<RuntimeEffectCounts, String> {
        validate_runtime_effects_for_admission(
            effects,
            allowed_tables,
            registered_intent_kinds,
            fact_admission,
        )?;
        store
            .write_transaction(|tx| {
                commit_runtime_effects_in_tx(
                    tx,
                    effects,
                    allowed_tables,
                    registered_intent_kinds,
                    fact_admission,
                    replay,
                    allow_rebuild,
                )
            })
            .map_err(|err| format!("{label}: {err}"))
    }

    pub(crate) fn commit_network_incoming_facts_to_db(
        store: &Db,
        facts: &[Fact],
        metadata: &IncomingMetadata,
        fact_admission: Option<FactAdmissionFn>,
        label: &str,
    ) -> Result<usize, String> {
        if let Some(fact_admission) = fact_admission {
            facts.iter().try_for_each(fact_admission)?;
        }
        store
            .write_transaction(|tx| {
                let mut inserted = 0usize;
                for fact in facts {
                    if super::insert_network_incoming_fact_in_tx(tx, fact, metadata)? {
                        inserted += 1;
                    }
                }
                Ok(inserted)
            })
            .map_err(|err| format!("{label}: {err}"))
    }

    /// Write all shared effects into an already-open transaction.
    ///
    /// The order is intentional: purges remove stale core-owned rows first,
    /// rebuild clears resettable state when requested, facts become pending, rows
    /// mutate, and follow-up intents are recorded last. If any step fails, the
    /// caller's transaction rolls the whole batch back.
    ///
    /// This function does not open or close the transaction. The caller owns the
    /// larger atomic boundary, which is why projection can update context and time
    /// wakes before committing these effects, and dispatch can delete the handled
    /// intent row in the same SQL unit.
    pub(crate) fn commit_runtime_effects_in_tx(
        tx: &Db,
        effects: &RuntimeEffects,
        allowed_tables: &[TableName],
        registered_intent_kinds: &[&str],
        fact_admission: Option<FactAdmissionFn>,
        replay: bool,
        allow_rebuild: bool,
    ) -> rusqlite::Result<RuntimeEffectCounts> {
        validate_runtime_effects(effects, allowed_tables, registered_intent_kinds)
            .map_err(sqlite_string_error)?;
        enforce_storage_requirement(tx, effects.storage_requirement)
            .map_err(sqlite_string_error)?;
        validate_fact_admissions(effects, fact_admission).map_err(sqlite_string_error)?;
        for purged in &effects.purged_facts {
            purge_fact_in_tx(tx, *purged)?;
        }

        if effects.rebuild_derived_state {
            if !allow_rebuild {
                return Err(sqlite_string_error(
                    "derived-state rebuild effect is only allowed from projection".to_string(),
                ));
            }
            commit_rebuild_effect_in_tx(tx).map_err(sqlite_string_error)?;
        }

        let mode = if replay {
            ProjectionMode::Replay
        } else {
            ProjectionMode::Normal
        };
        let facts = insert_facts_and_record_matches_with_mode_in_tx(tx, &effects.facts, mode)?
            + insert_priority_facts_and_record_matches_with_mode_in_tx(
                tx,
                &effects.priority_facts,
                mode,
            )?;

        for fact in &effects.incoming_facts {
            let metadata = effects.incoming_fact_metadata.get(&fact.id);
            insert_incoming_fact_with_metadata_in_tx(tx, fact, metadata)?;
        }

        validate_row_mutations(&effects.row_mutations, allowed_tables)
            .map_err(sqlite_string_error)?;
        tx.apply_row_mutations_in_tx(&effects.row_mutations)?;

        let intents = insert_intents_in_tx(
            tx,
            crate::core::handle_intent::IntentQueue::Durable,
            &effects.intents,
            replay,
        )?;
        let local_intents = insert_intents_in_tx(
            tx,
            crate::core::handle_intent::IntentQueue::Local,
            &effects.local_intents,
            replay,
        )?;

        Ok(RuntimeEffectCounts {
            facts,
            intents,
            local_intents,
        })
    }

    fn commit_rebuild_effect_in_tx(tx: &Db) -> Result<(), String> {
        clear_resettable_derived_state_in_tx(tx)
            .map_err(|err| format!("clear resettable derived state: {err}"))?;
        enqueue_retained_facts_for_replay_in_tx(tx)?;
        Ok(())
    }

    fn clear_resettable_derived_state_in_tx(tx: &Db) -> rusqlite::Result<()> {
        for table in tx.replay_reset_tables() {
            let quoted = crate::core::db::quoted_table_name(*table)?;
            tx.conn().execute(&format!("DELETE FROM {quoted}"), [])?;
        }
        Ok(())
    }

    fn enqueue_retained_facts_for_replay_in_tx(tx: &Db) -> Result<(), String> {
        tx.conn()
            .execute(
                "INSERT OR IGNORE INTO pending_projection (owner, queued_at, priority, replay)
                 SELECT f.id, m.received_at, 100, 1
                 FROM facts f
                 JOIN local_fact_admissions m ON m.fact_id = f.id",
                [],
            )
            .map_err(|err| format!("enqueue retained facts for replay: {err}"))?;
        Ok(())
    }

    fn enforce_storage_requirement(tx: &Db, requirement: StorageRequirement) -> Result<(), String> {
        match requirement {
            StorageRequirement::MaintenanceBypass => Ok(()),
            StorageRequirement::Current(version) => tx.require_storage_version(version),
        }
    }

    pub(crate) fn storage_requirement_satisfied(
        tx: &Db,
        requirement: StorageRequirement,
    ) -> Result<bool, String> {
        match requirement {
            StorageRequirement::MaintenanceBypass => Ok(true),
            StorageRequirement::Current(version) => tx
                .current_storage_version()
                .map(|stored| stored == Some(version))
                .map_err(|err| format!("read storage version marker: {err}")),
        }
    }

    fn insert_intents_in_tx(
        tx: &Db,
        queue: crate::core::handle_intent::IntentQueue,
        intents: &[Intent],
        replay: bool,
    ) -> rusqlite::Result<usize> {
        let mut inserted = 0usize;
        for intent in intents {
            let mode = if replay {
                crate::core::intents::HandlerMode::Replay
            } else {
                crate::core::intents::HandlerMode::Live
            };
            crate::core::handle_intent::insert_intent_in_tx(tx, queue, intent, mode)?;
            inserted += 1;
        }
        Ok(inserted)
    }
}
pub mod context {
    //! Projection context visible while processing one fact.

    use super::effects::{TimeRange, Timeline};
    use super::IncomingMetadata;
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
        incoming_metadata: Option<IncomingMetadata>,
    }

    /// One matched need/offer pair plus the offer value as a compatibility fact.
    ///
    /// Core constructs this from standing context rows before calling the
    /// projector. New projectors should prefer `value_for`. The `payload` field
    /// exists for legacy projectors and is built from the stored offer value, not
    /// by loading the offer owner's retained fact bytes.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub struct MatchedContext {
        /// The need owned by the fact currently being projected.
        pub need: ContextNeed,
        /// The offer that satisfied the need.
        pub offer: ContextOffer,
        /// Compatibility wrapper whose bytes are the matched offer value.
        pub payload: Fact,
    }

    impl ProjectionContext {
        /// Build context containing only unmatched standing offers.
        ///
        /// This shape is mainly used for facts with no needs; protocol code should
        /// prefer the matched-payload helpers when a proof depends on a need.
        pub fn new(offers: Vec<ContextOffer>) -> Self {
            Self {
                offers,
                ..Self::default()
            }
        }

        /// Build context from already matched need/offer/payload triples.
        pub fn from_matches(matched: Vec<MatchedContext>) -> Self {
            let matched = matched
                .into_iter()
                .map(normalized_matched_context)
                .collect::<Vec<_>>();
            let mut offers = matched
                .iter()
                .map(|matched| matched.offer.clone())
                .collect::<Vec<_>>();
            offers.sort();
            offers.dedup();
            let matched_by_need = index_matches_by_need(&matched);
            Self {
                offers,
                matched,
                matched_by_need,
                ..Self::default()
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

        /// Attach receive metadata for an outside-origin projection input.
        pub fn with_incoming_metadata(mut self, metadata: IncomingMetadata) -> Self {
            self.incoming_metadata = Some(metadata);
            self
        }

        /// Return receive metadata for the current incoming projection input.
        pub fn incoming_metadata(&self) -> Option<&IncomingMetadata> {
            self.incoming_metadata.as_ref()
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

        /// Return a fact-shaped compatibility wrapper for one exact need, if any.
        ///
        /// The returned bytes are the stored offer value. This is a lookup over
        /// context core already matched and hydrated before projection. It does
        /// not query storage or run overlap queries.
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

        /// Return the scalar offer value supplied for an exact need, if any.
        pub fn value_for(&self, need: &ContextNeed) -> Option<&[u8]> {
            self.matched_entries_for(need)
                .next()
                .map(|matched| matched.offer.value.as_slice())
        }

        /// Return every matched compatibility payload for a need.
        ///
        /// The payload bytes are stored offer values. This helper remains for
        /// legacy fact-shaped wrappers and intentional multi-match roles.
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

    fn normalized_matched_context(mut matched: MatchedContext) -> MatchedContext {
        if matched.offer.value.is_empty() && !matched.payload.bytes.is_empty() {
            matched.offer.value = matched.payload.bytes.clone();
        } else if matched.payload.bytes.is_empty() && !matched.offer.value.is_empty() {
            matched.payload.bytes = matched.offer.value.clone();
        }
        matched
    }
}
pub(crate) mod context_db;

pub mod effects {
    //! Projection effects and time-wake output for fact projectors.

    use crate::core::context::{ContextKey, ContextNeed, ContextOffer, ContextSet, Role};
    use crate::core::effects::{IncomingMetadata, RuntimeEffects};
    use crate::core::facts::{Fact, FactId};
    use crate::core::intents::{Intent, RowMutation};

    const FACT_PURGED_ROLE: &str = "fact_purged";

    /// Context role used by deletion/retention projectors to wake a target fact.
    ///
    /// Core treats purge keys opaquely. Protocol families choose their own stable
    /// key shape and validate matched offer values before treating this context as
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
            key,
        }
    }

    pub fn fact_purged_offer(
        owner: FactId,
        scope: crate::core::facts::FactScope,
        key: ContextKey,
    ) -> ContextOffer {
        fact_purged_range_offer(owner, scope, key.clone(), key)
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
            value: Vec::new(),
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
        /// Whether an incoming input should become a retained fact after successful
        /// projection. Durable facts are already retained, so this only affects
        /// `ProjectionSource::Incoming` items.
        pub retain_self: bool,
        /// Complete replacement needs for the projected fact.
        pub needs: Vec<ContextNeed>,
        /// New durable offers for the projected fact.
        pub offers: Vec<ContextOffer>,
        /// Complete replacement time wakes for the projected fact.
        pub time_wakes: Vec<TimeWake>,
        /// Child facts, self-purge, row mutations, and intents to commit with this projection.
        pub effects: RuntimeEffects,
    }

    impl Default for ProjectionOutput {
        fn default() -> Self {
            Self {
                retain_self: true,
                needs: Vec::new(),
                offers: Vec::new(),
                time_wakes: Vec::new(),
                effects: RuntimeEffects::default(),
            }
        }
    }

    impl ProjectionOutput {
        pub fn new() -> Self {
            Self::default()
        }

        /// Drop a volatile incoming fact after this projection instead of retaining it.
        ///
        /// This is for transport wrappers and other one-shot incoming facts. It has
        /// no effect on already retained facts.
        pub fn drop_incoming(mut self) -> Self {
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

        /// Request a database-wide rebuild of derived/runtime state.
        ///
        /// This is intentionally much broader than `purge_self`: the commit
        /// boundary clears schema-declared resettable tables and requeues every
        /// retained fact in replay mode. Protocols should reserve it for local
        /// control-plane facts whose replay-mode projector is a no-op, so the
        /// retained record remains auditable without re-triggering the rebuild.
        pub fn rebuild_derived_state(mut self) -> Self {
            self.effects.rebuild_derived_state = true;
            self
        }

        pub fn fact(mut self, fact: Fact) -> Self {
            self.effects.facts.push(fact);
            self
        }

        pub fn incoming_fact(mut self, fact: Fact) -> Self {
            self.effects.incoming_facts.push(fact);
            self
        }

        pub fn incoming_fact_with_metadata(
            mut self,
            fact: Fact,
            metadata: IncomingMetadata,
        ) -> Self {
            self.effects
                .incoming_fact_metadata
                .insert(fact.id, metadata);
            self.effects.incoming_facts.push(fact);
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

    // =========================================================================
    // Tests
    // =========================================================================
    //
    // Ordered most-central first: purge need/offer key matching is what lets a
    // deletion offer wake the target it purges, so the exact-key base case leads.

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
            assert_eq!(need.key, offer.start_key);
            assert_eq!(offer.start_key, offer.end_key);
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
            assert!(offer.start_key <= need.key);
            assert!(offer.end_key >= need.key);
        }
    }
}
pub mod route {
    //! Fact route selection for read projection.

    use super::context::ProjectionContext;
    use super::effects::ProjectionOutput;
    use crate::core::effects::StorageRequirement;
    use crate::core::facts::Fact;

    /// Function pointer used by static projector route tables.
    pub type ProjectorFn = fn(&Fact, &ProjectionContext) -> Result<ProjectionOutput, String>;
    /// Optional protocol-owned admission check for facts core is about to store.
    pub type FactAdmissionFn = fn(&Fact) -> Result<(), String>;
    /// Function that maps an envelope fact to its semantic fact tag.
    pub type EffectiveTagFn = fn(&Fact) -> Result<u8, String>;

    /// Human-readable projector declaration for a fact route.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FactProjectorInfo {
        /// Projector implementation that owns this tag's local fact semantics.
        pub project: &'static str,
    }

    impl FactProjectorInfo {
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
        /// Storage version required by this route's committed effects.
        pub storage_requirement: StorageRequirement,
        /// Projector metadata for this route.
        pub projector_info: FactProjectorInfo,
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
            let output = (route.projector)(fact, context)?;
            Ok(ProjectionOutput {
                effects: output
                    .effects
                    .with_storage_requirement(route.storage_requirement),
                ..output
            })
        }
    }
}

pub use context::{MatchedContext, ProjectionContext, ProjectionMode};
pub use effects::{
    fact_purged_need, fact_purged_offer, fact_purged_range_offer, fact_purged_role,
    ProjectionOutput, TimeRange, TimeWake, Timeline,
};
pub use route::{
    EffectiveTagFn, EnvelopeRoute, FactAdmissionFn, FactProjectorInfo, FactRoute, Projector,
    ProjectorFn, RouterProjector,
};

const OWNER_KEYED_FACT_CLEANUP_TABLES: &[TableName] = &[
    CONTEXT_NEEDS,
    CONTEXT_EXACT_OFFERS,
    CONTEXT_RANGE_OFFERS,
    TIME_WAKES,
    PENDING_TIME_RANGES,
    PENDING_PROJECTION_MATCHES,
    PENDING_PROJECTION,
];
const CONTROL_PROJECTION_PRIORITY: i64 = 0;
const NORMAL_PROJECTION_PRIORITY: i64 = 100;

fn projection_sql_error(message: impl Into<String>) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(message.into())
}

fn verify_idempotent_insert<T>(
    changed: usize,
    existing: impl FnOnce() -> rusqlite::Result<Option<T>>,
    matches_existing: impl FnOnce(&T) -> bool,
    conflict_message: impl Into<String>,
) -> rusqlite::Result<bool> {
    if changed == 0 {
        let matches = existing()?.as_ref().map(matches_existing).unwrap_or(false);
        if !matches {
            return Err(projection_sql_error(conflict_message));
        }
    }
    Ok(changed > 0)
}

#[cfg(test)]
fn retained_fact(store: &Db, id: &FactId) -> Result<Option<Fact>, String> {
    store
        .conn()
        .query_row(
            "SELECT f.id, m.scope, m.scope_kind, m.scope_id, m.received_at, f.bytes
             FROM facts f
             JOIN local_fact_admissions m ON m.fact_id = f.id
             WHERE f.id = ?1
             LIMIT 1",
            params![id.as_slice()],
            validate_fact_query_result,
        )
        .optional()
        .map_err(|err| format!("load retained fact: {err}"))
}

#[cfg(test)]
pub(crate) fn insert_fact_and_pending_in_tx(store: &Db, fact: &Fact) -> rusqlite::Result<bool> {
    insert_fact_and_pending_with_mode_in_tx(store, fact, ProjectionMode::Normal)
}

fn insert_fact_and_pending_with_mode_in_tx(
    store: &Db,
    fact: &Fact,
    mode: ProjectionMode,
) -> rusqlite::Result<bool> {
    insert_fact_and_pending_with_options_in_tx(store, fact, mode, NORMAL_PROJECTION_PRIORITY)
}

fn insert_priority_fact_and_pending_with_mode_in_tx(
    store: &Db,
    fact: &Fact,
    mode: ProjectionMode,
) -> rusqlite::Result<bool> {
    insert_fact_and_pending_with_options_in_tx(store, fact, mode, CONTROL_PROJECTION_PRIORITY)
}

/// Insert a fact and mark it pending with the supplied execution mode and queue priority.
fn insert_fact_and_pending_with_options_in_tx(
    store: &Db,
    fact: &Fact,
    mode: ProjectionMode,
    priority: i64,
) -> rusqlite::Result<bool> {
    let inserted = insert_retained_fact_in_tx(store, fact)?;
    if inserted {
        insert_pending_owner_with_options_in_tx(store, fact.id, mode, priority)?;
    }
    Ok(inserted)
}

fn insert_facts_and_record_matches_in_tx(store: &Db, facts: &[Fact]) -> rusqlite::Result<usize> {
    insert_facts_and_record_matches_with_mode_in_tx(store, facts, ProjectionMode::Normal)
}

fn insert_facts_and_record_matches_with_mode_in_tx(
    store: &Db,
    facts: &[Fact],
    mode: ProjectionMode,
) -> rusqlite::Result<usize> {
    let mut inserted = 0;
    for fact in facts {
        if insert_fact_and_pending_with_mode_in_tx(store, fact, mode)? {
            context_db::record_pending_context_inputs_for_stored_needs_in_tx(store, fact.id)
                .map_err(commit_effects::sqlite_string_error)?;
            inserted += 1;
        }
    }
    Ok(inserted)
}

fn insert_priority_facts_and_record_matches_with_mode_in_tx(
    store: &Db,
    facts: &[Fact],
    mode: ProjectionMode,
) -> rusqlite::Result<usize> {
    let mut inserted = 0;
    for fact in facts {
        if insert_priority_fact_and_pending_with_mode_in_tx(store, fact, mode)? {
            context_db::record_pending_context_inputs_for_stored_needs_in_tx(store, fact.id)
                .map_err(commit_effects::sqlite_string_error)?;
            inserted += 1;
        }
    }
    Ok(inserted)
}

fn insert_pending_owner_in_tx(store: &Db, owner: FactId) -> rusqlite::Result<usize> {
    insert_pending_owner_with_mode_in_tx(store, owner, ProjectionMode::Normal)
}

fn insert_pending_owner_with_mode_in_tx(
    store: &Db,
    owner: FactId,
    mode: ProjectionMode,
) -> rusqlite::Result<usize> {
    insert_pending_owner_with_options_in_tx(store, owner, mode, NORMAL_PROJECTION_PRIORITY)
}

fn insert_pending_owner_with_options_in_tx(
    store: &Db,
    owner: FactId,
    mode: ProjectionMode,
    priority: i64,
) -> rusqlite::Result<usize> {
    let inserted = store.conn().execute(
        "INSERT OR IGNORE INTO pending_projection (owner, queued_at, priority, replay)
         VALUES (?1, ?2, ?3, ?4)",
        params![
            owner.as_slice(),
            queue_now_ms()?,
            priority,
            replay_flag_for_projection_mode(mode)
        ],
    )?;
    if inserted == 0 && mode.is_replay() {
        store.conn().execute(
            "UPDATE pending_projection
             SET replay = 1,
                 priority = MIN(priority, ?2)
             WHERE owner = ?1",
            params![owner.as_slice(), priority],
        )?;
    } else if inserted == 0 && priority < NORMAL_PROJECTION_PRIORITY {
        store.conn().execute(
            "UPDATE pending_projection
             SET priority = MIN(priority, ?2)
             WHERE owner = ?1",
            params![owner.as_slice(), priority],
        )?;
    }
    Ok(inserted)
}

fn replay_flag_for_projection_mode(mode: ProjectionMode) -> i64 {
    if mode.is_replay() {
        1
    } else {
        0
    }
}

pub(crate) fn insert_network_incoming_fact_in_tx(
    store: &Db,
    fact: &Fact,
    metadata: &IncomingMetadata,
) -> rusqlite::Result<bool> {
    insert_incoming_fact_with_metadata_in_tx(store, fact, Some(metadata))
}

#[cfg(test)]
fn insert_incoming_fact_in_tx(store: &Db, fact: &Fact) -> rusqlite::Result<bool> {
    insert_incoming_fact_with_metadata_in_tx(store, fact, None)
}

fn insert_incoming_fact_with_metadata_in_tx(
    store: &Db,
    fact: &Fact,
    metadata: Option<&IncomingMetadata>,
) -> rusqlite::Result<bool> {
    if let Some(bytes) = fact_bytes_by_id_in_tx(store, &fact.id)? {
        if bytes == fact.bytes {
            return Ok(false);
        }
        return Err(projection_sql_error(
            "conflicting retained row for incoming fact",
        ));
    }

    let (scope, scope_kind, scope_id) = fact.scope.storage_columns();
    let origin_addr = metadata.map(|metadata| metadata.origin_addr.as_slice());
    let origin_received_at = metadata
        .map(|metadata| sqlite_u64(metadata.received_at_local_ms, "incoming origin received_at"))
        .transpose()?;
    let staged_at = queue_now_ms()?;
    let changed = store.conn().execute(
        "INSERT OR IGNORE INTO incoming_facts
            (
                id,
                scope,
                scope_kind,
                scope_id,
                received_at,
                staged_at,
                bytes,
                origin_addr,
                origin_received_at
            )
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            fact.id.as_slice(),
            scope,
            scope_kind,
            scope_id.as_slice(),
            sqlite_u64(fact.timestamp, "incoming fact received_at")?,
            staged_at,
            fact.bytes.as_slice(),
            origin_addr,
            origin_received_at,
        ],
    )?;
    verify_idempotent_insert(
        changed,
        || incoming_fact_by_id_in_tx(store, &fact.id),
        |existing| existing.bytes == fact.bytes,
        "conflicting row for incoming fact",
    )
}

fn delete_incoming_fact_in_tx(store: &Db, owner: FactId) -> rusqlite::Result<bool> {
    let changed =
        delete_rows_by_blob_column_in_tx(store, INCOMING_FACTS, "id", owner.as_slice())? > 0;
    if changed {
        delete_owner_rows_from_tables(store, OWNER_KEYED_FACT_CLEANUP_TABLES, owner)?;
    }
    Ok(changed)
}

fn move_incoming_to_retained_in_tx(store: &Db, fact: &Fact) -> rusqlite::Result<bool> {
    let retained = insert_retained_fact_in_tx(store, fact)?;
    delete_incoming_fact_in_tx(store, fact.id)?;
    Ok(retained)
}

fn purge_fact_in_tx(store: &Db, owner: FactId) -> rusqlite::Result<bool> {
    let mut changed = delete_rows_by_blob_column_in_tx(store, FACTS, "id", owner.as_slice())? > 0;
    changed |= delete_rows_by_blob_column_in_tx(
        store,
        LOCAL_FACT_ADMISSIONS,
        "fact_id",
        owner.as_slice(),
    )? > 0;
    changed |= delete_pending_matches_for_offer_owner_in_tx(store, owner)? > 0;
    changed |= delete_owner_rows_from_tables(store, OWNER_KEYED_FACT_CLEANUP_TABLES, owner)? > 0;
    Ok(changed)
}

fn insert_retained_fact_in_tx(store: &Db, fact: &Fact) -> rusqlite::Result<bool> {
    let fact_bytes_inserted = insert_fact_bytes_in_tx(store, fact)?;
    let admission_inserted = insert_local_fact_admission_in_tx(store, fact)? > 0;
    Ok(fact_bytes_inserted || admission_inserted)
}

fn sqlite_u64(value: u64, name: &str) -> rusqlite::Result<i64> {
    i64::try_from(value).map_err(|_| {
        projection_sql_error(format!("{name}: SQL value exceeds SQLite integer range"))
    })
}

fn queue_now_ms() -> rusqlite::Result<i64> {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|err| projection_sql_error(format!("queue clock before Unix epoch: {err}")))?;
    let millis = duration.as_millis();
    i64::try_from(millis).map_err(|_| projection_sql_error("queue timestamp exceeds SQLite range"))
}

fn insert_fact_bytes_in_tx(store: &Db, fact: &Fact) -> rusqlite::Result<bool> {
    let changed = store.conn().execute(
        "INSERT OR IGNORE INTO facts (id, bytes) VALUES (?1, ?2)",
        params![fact.id.as_slice(), fact.bytes.as_slice()],
    )?;
    verify_idempotent_insert(
        changed,
        || fact_bytes_by_id_in_tx(store, &fact.id),
        |existing| existing.as_slice() == fact.bytes.as_slice(),
        "conflicting row for facts",
    )
}

fn insert_local_fact_admission_in_tx(store: &Db, fact: &Fact) -> rusqlite::Result<usize> {
    let (scope, scope_kind, scope_id) = fact.scope.storage_columns();
    let received_at = sqlite_u64(fact.timestamp, "fact received_at")?;
    let bytes = local_fact_admission_bytes(fact)?;
    let id = fact_id(&bytes);
    store.conn().execute(
        "INSERT OR IGNORE INTO local_fact_admissions
            (id, fact_id, scope, scope_kind, scope_id, received_at, bytes)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            id.as_slice(),
            fact.id.as_slice(),
            scope,
            scope_kind,
            scope_id.as_slice(),
            received_at,
            bytes.as_slice()
        ],
    )
}

fn local_fact_admission_bytes(fact: &Fact) -> rusqlite::Result<Vec<u8>> {
    let (scope, scope_kind, scope_id) = fact.scope.storage_columns();
    let mut out = Writer::new();
    out.bytes(b"topo:local_fact_admission:v1");
    out.fixed(&fact.id);
    out.string_u32be(scope)
        .map_err(|err| local_fact_admission_wire_error("scope", err))?;
    out.string_u32be(scope_kind)
        .map_err(|err| local_fact_admission_wire_error("scope_kind", err))?;
    out.fixed(scope_id);
    out.u64be(fact.timestamp);
    Ok(out.finish())
}

fn local_fact_admission_wire_error(
    field: &str,
    err: crate::core::wire::WireError,
) -> rusqlite::Error {
    projection_sql_error(format!("local fact admission {field}: {err}"))
}

fn incoming_fact_by_id_in_tx(store: &Db, id: &FactId) -> rusqlite::Result<Option<Fact>> {
    store
        .conn()
        .query_row(
            "SELECT id, scope, scope_kind, scope_id, received_at, bytes
             FROM incoming_facts
             WHERE id = ?1
             LIMIT 1",
            params![id.as_slice()],
            validate_fact_query_result,
        )
        .optional()
}

/// Load transport-origin metadata for an incoming first-pass fact.
///
/// This metadata is intentionally limited to `incoming_facts`: it describes how
/// outside-origin bytes reached this process before admission. If projection
/// later retains the fact, the durable fact keeps normal local admission
/// metadata, while timing diagnostics may preserve the original receive time.
fn incoming_origin_metadata_by_id(
    store: &Db,
    id: &FactId,
) -> rusqlite::Result<Option<IncomingMetadata>> {
    store
        .conn()
        .query_row(
            "SELECT origin_addr, origin_received_at
             FROM incoming_facts
             WHERE id = ?1
             LIMIT 1",
            params![id.as_slice()],
            metadata_from_optional_columns,
        )
        .optional()
        .map(|row| row.flatten())
}

fn metadata_from_optional_columns(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<Option<IncomingMetadata>> {
    let origin_addr = row.get::<_, Option<Vec<u8>>>(0)?;
    let received_at = row.get::<_, Option<i64>>(1)?;
    match (origin_addr, received_at) {
        (Some(origin_addr), Some(received_at)) => Ok(Some(IncomingMetadata {
            origin_addr,
            received_at_local_ms: u64_column(received_at, "incoming origin received_at")?,
        })),
        (None, None) => Ok(None),
        _ => Err(projection_sql_error(
            "incoming origin metadata columns must both be set or both be null",
        )),
    }
}

fn fact_bytes_by_id_in_tx(store: &Db, id: &FactId) -> rusqlite::Result<Option<Vec<u8>>> {
    store
        .conn()
        .query_row(
            "SELECT bytes FROM facts WHERE id = ?1 LIMIT 1",
            params![id.as_slice()],
            |row| row.get(0),
        )
        .optional()
}

fn delete_rows_by_blob_column_in_tx(
    store: &Db,
    table: TableName,
    column: &str,
    value: &[u8],
) -> rusqlite::Result<usize> {
    let table = quoted_table_name(table)?;
    let column = quoted_identifier(column)?;
    store.conn().execute(
        &format!("DELETE FROM {table} WHERE {column} = ?1"),
        params![value],
    )
}

fn delete_owner_rows_from_tables(
    store: &Db,
    tables: &[TableName],
    owner: FactId,
) -> rusqlite::Result<usize> {
    let mut deleted = 0usize;
    for table in tables {
        deleted += delete_rows_by_owner_in_tx(store, *table, owner)?;
    }
    Ok(deleted)
}

pub(crate) fn pending_projection_input_count(store: &Db) -> usize {
    store
        .table_row_count(PENDING_PROJECTION)
        .expect("pending projection count should load from database")
        + store
            .table_row_count(INCOMING_FACTS)
            .expect("incoming fact count should load from database")
}

/// Admit one fact after the runtime's protocol admission check.
pub(crate) fn submit_fact_with_admission(
    store: &Db,
    fact: Fact,
    fact_admission: Option<FactAdmissionFn>,
) -> Result<bool, String> {
    submit_facts_with_admission(store, [fact], fact_admission).map(|inserted| inserted > 0)
}

/// Admit many facts after the runtime's protocol admission check.
pub(crate) fn submit_facts_with_admission(
    store: &Db,
    facts: impl IntoIterator<Item = Fact>,
    fact_admission: Option<FactAdmissionFn>,
) -> Result<usize, String> {
    let facts = facts.into_iter().collect::<Vec<_>>();
    if let Some(admit) = fact_admission {
        facts.iter().try_for_each(admit)?;
    }
    submit_facts_to_db(store, facts)
}

/// Commit command-authored facts and return the command receipt.
pub(crate) fn submit_authored_facts_to_db<T>(
    store: &Db,
    output: AuthoredFacts<T>,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    label: &str,
) -> Result<T, String> {
    let (receipt, facts) = output.into_parts();
    let effects = RuntimeEffects {
        facts,
        ..RuntimeEffects::new()
    };
    commit_runtime_effects_to_db(
        store,
        &effects,
        allowed_tables,
        &[],
        fact_admission,
        false,
        false,
        label,
    )?;
    Ok(receipt)
}

/// Turn due time wakes into pending projection work.
pub(crate) fn process_due_time_range(
    store: &Db,
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

/// Bulk insert facts with one transaction and one pending row per insert.
pub(crate) fn submit_facts_to_db(
    store: &Db,
    facts: impl IntoIterator<Item = Fact>,
) -> Result<usize, String> {
    let facts = facts.into_iter().collect::<Vec<_>>();
    store
        .write_transaction(|tx| insert_facts_and_record_matches_in_tx(tx, &facts))
        .map_err(|err| format!("submit facts: {err}"))
}

fn enqueue_due_time_wakes_in_tx(
    store: &Db,
    range: &TimeRange,
    limit: usize,
) -> rusqlite::Result<usize> {
    let owners = due_time_wake_owners(store, range, limit)?;
    let has_start = range.start_exclusive.is_some();
    let has_start_i64 = i64::from(has_start);
    let start_exclusive = sqlite_u64(range.start_exclusive.unwrap_or(0), "start_exclusive")?;
    let end_inclusive = sqlite_u64(range.end_inclusive, "end_inclusive")?;

    let mut inserted = 0;
    for owner in owners {
        inserted += insert_pending_owner_in_tx(store, owner)?;
        context_db::record_pending_context_inputs_for_stored_needs_in_tx(store, owner).map_err(
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

/// Load due time ranges attached to this pending projection owner.
///
/// Time wakes are recorded as pending inputs when the runtime admits a due
/// semantic-time range. The projector receives these ranges through
/// `ProjectionContext` in the same way it receives context matches: as a
/// snapshot for this run, not as a live query against standing wake state.
fn pending_time_ranges_for_owner(store: &Db, owner: FactId) -> Result<Vec<TimeRange>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT timeline, has_start, start_exclusive, end_inclusive
             FROM pending_time_ranges
             WHERE owner = ?1
             ORDER BY timeline, has_start, start_exclusive, end_inclusive",
        )
        .map_err(|err| format!("load pending time ranges: {err}"))?;
    let rows = stmt
        .query_map(params![owner.as_slice()], decode_pending_time_range)
        .map_err(|err| format!("load pending time ranges: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("load pending time ranges: {err}"))
}

/// Decode the SQL representation of a pending semantic-time range.
fn decode_pending_time_range(row: &rusqlite::Row<'_>) -> rusqlite::Result<TimeRange> {
    let start_exclusive = match row.get::<_, i64>(1)? {
        0 => None,
        1 => Some(u64_column(row.get::<_, i64>(2)?, "start_exclusive")?),
        other => {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "pending time range has invalid bool {other}"
            )));
        }
    };

    Ok(TimeRange {
        timeline: Timeline::new(row.get::<_, String>(0)?)
            .map_err(rusqlite::Error::InvalidParameterName)?,
        start_exclusive,
        end_inclusive: u64_column(row.get::<_, i64>(3)?, "end_inclusive")?,
    })
}

fn due_time_wake_owners(
    store: &Db,
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

fn fact_id_column(bytes: Vec<u8>, name: &str) -> rusqlite::Result<FactId> {
    bytes.try_into().map_err(|_| {
        rusqlite::Error::InvalidParameterName(format!("{name} is not a 32-byte fact id"))
    })
}

fn u64_column(value: i64, name: &str) -> rusqlite::Result<u64> {
    u64::try_from(value)
        .map_err(|_| rusqlite::Error::InvalidParameterName(format!("{name} is negative")))
}

// =============================================================================
// Tests
// =============================================================================
//
// `contract_tests` exercises the SQL-backed projection worker end to end and is
// ordered most-central first: the queue/context wake loop and the incoming
// retention lifecycle lead, failure isolation and the safety guards follow, and
// the narrow owner/metadata/index checks come last. A reader going top-down sees
// how a fact flows through load -> evaluate -> commit before the edge cases.

#[cfg(test)]
mod contract_tests {
    use super::*;
    use crate::core::context::{ContextKey, ContextNeed, ContextOffer, ContextSetAdditions, Role};
    use crate::core::effects::StorageRequirement;
    use crate::core::facts::{FactId, FactScope, ScopeKind};
    use crate::core::intents::{Intent, IntentKind};
    use crate::core::schema::CORE_SCHEMA_SOURCE;
    use rusqlite::OptionalExtension;
    use std::cell::Cell;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const TEST_REGISTERED_INTENT_KINDS: &[&str] = &[
        "ephemeral_partial",
        "ephemeral_ready",
        "followup",
        "multi_stage_ready",
        "observed",
        "premature",
        "queue_ready",
        "queued_context_ready",
        "ready",
        "readded_ready",
        "semantic_ready",
    ];

    fn submit_fact_to_db(store: &Db, fact: Fact) -> Result<bool, String> {
        submit_facts_to_db(store, [fact]).map(|inserted| inserted > 0)
    }

    fn run_projection(
        projector: &(impl Projector + ?Sized),
        fact: &Fact,
        pending_inputs: ProjectionContext,
    ) -> Result<PreparedProjection, String> {
        run_projection_with_registered_intents(
            projector,
            fact,
            pending_inputs,
            TEST_REGISTERED_INTENT_KINDS,
        )
    }

    fn run_projection_with_registered_intents(
        projector: &(impl Projector + ?Sized),
        fact: &Fact,
        pending_inputs: ProjectionContext,
        registered_intent_kinds: &[&str],
    ) -> Result<PreparedProjection, String> {
        prepare_projection(
            projector,
            ProjectionInput {
                source: ProjectionSource::Durable,
                fact: fact.clone(),
                input_staged_at_ms: None,
                pending_inputs,
            },
            test_effect_policy(registered_intent_kinds),
        )
    }

    fn test_effect_policy<'a>(
        registered_intent_kinds: &'a [&'a str],
    ) -> ProjectionEffectPolicy<'a, 'a> {
        ProjectionEffectPolicy {
            allowed_tables: &[],
            registered_intent_kinds,
            fact_admission: None,
        }
    }

    fn expect_loaded(load: Option<ProjectionLoad>) -> ProjectionInput {
        match load.expect("queued input") {
            ProjectionLoad::Loaded(input) => input,
            ProjectionLoad::Stale { .. } => panic!("expected loaded projection input"),
        }
    }

    static VERSION_GUARD_PROJECTOR_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn version_guard_projector(
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        VERSION_GUARD_PROJECTOR_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(ProjectionOutput::new().need(ContextNeed::for_key(
            fact.id,
            "version_guard",
            FactScope::Global,
            [7; 32],
        )))
    }

    const VERSION_GUARD_ROUTES: &[FactRoute] = &[FactRoute {
        tag: 201,
        projector: version_guard_projector,
        storage_requirement: StorageRequirement::Current(7),
        projector_info: FactProjectorInfo::projector("version_guard_projector"),
    }];

    #[test]
    fn projection_drain_revisits_dependent_after_offer_commits() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let offered = Fact::new(FactScope::Global, 1, b"queue-offer".to_vec());
        let dependent = Fact::new(FactScope::Global, 2, b"queue-dependent".to_vec());
        submit_fact_to_db(&store, dependent.clone()).expect("submit dependent first");

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

        assert!(first);
        assert_eq!(pending_projection_count(&store, dependent.id), 0);
        let parked_context = stored_context_for_owner(&store, &dependent.id).expect("parked");
        assert_eq!(parked_context.needs.len(), 1);

        submit_fact_to_db(&store, offered.clone()).expect("submit offer");
        let progress =
            drain_projection(&projector, &store, &[], None, 3).expect("drain queued dependency");

        assert!(progress);
        let payload = intent_payload_for(&store, "queue_ready", &dependent.id);
        assert_eq!(payload, offered.id.to_vec());
        let dependent_context =
            stored_context_for_owner(&store, &dependent.id).expect("dependent context");
        assert!(dependent_context.needs.is_empty());
        assert_eq!(pending_projection_count(&store, offered.id), 0);
        assert_eq!(pending_projection_count(&store, dependent.id), 0);
    }

    #[test]
    fn matched_context_uses_offer_value_not_breaking_older_fact_bytes() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let producer = Fact::new(
            FactScope::Global,
            1,
            b"author-v0|profile:ada|user:ada".to_vec(),
        );
        let consumer = Fact::new(FactScope::Global, 2, b"needs-author-profile:ada".to_vec());
        let role = Role::new("author_profile").unwrap();
        let key = ContextKey::from_bytes(b"profile:ada");
        let offered_value = b"user:ada".to_vec();

        assert!(
            decode_v1_author_fact(producer.body()).is_err(),
            "the retained producer bytes intentionally use an older layout"
        );
        submit_fact_to_db(&store, consumer.clone()).expect("submit dependent first");

        let projector = SemanticOfferProjector {
            producer_id: producer.id,
            consumer_id: consumer.id,
            role: role.clone(),
            key: key.clone(),
            offered_value: offered_value.clone(),
        };
        let first = drain_projection(&projector, &store, &[], None, 1)
            .expect("consumer parks on missing semantic offer");

        assert!(first);
        assert_eq!(pending_projection_count(&store, consumer.id), 0);
        assert!(stored_context_for_owner(&store, &consumer.id)
            .expect("consumer context")
            .offers
            .is_empty());

        submit_fact_to_db(&store, producer.clone()).expect("submit producer");
        let second =
            drain_projection(&projector, &store, &[], None, 3).expect("producer wakes consumer");

        assert!(second);
        assert_eq!(
            intent_payload_for(&store, "semantic_ready", &consumer.id),
            offered_value
        );
        let producer_context =
            stored_context_for_owner(&store, &producer.id).expect("producer context");
        assert_eq!(producer_context.offers.len(), 1);
        assert_eq!(producer_context.offers[0].value, b"user:ada".to_vec());
        assert_ne!(producer_context.offers[0].value, producer.bytes);
    }

    #[test]
    fn matched_context_preserves_offer_owner_metadata_for_legacy_payloads() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let producer_scope = FactScope::Scoped {
            kind: ScopeKind::new("owner_meta").unwrap(),
            id: [9; 32],
        };
        let producer = Fact::new(producer_scope.clone(), 41, b"producer-fact-v0".to_vec());
        let consumer = Fact::new(FactScope::Global, 42, b"consumer-needs-value".to_vec());
        let role = Role::new("owner_meta").unwrap();
        let key = ContextKey::from_bytes(b"producer-value");
        let value = b"semantic-value".to_vec();

        submit_fact_to_db(&store, consumer.clone()).expect("submit consumer");

        let projector = test_projector({
            let role = role.clone();
            let key = key.clone();
            let producer_scope = producer_scope.clone();
            let producer_id = producer.id;
            let consumer_id = consumer.id;
            let value = value.clone();
            move |fact, context| {
                if fact.id == producer_id {
                    return Ok(ProjectionOutput::new().offer(ContextOffer::for_key_value(
                        fact.id,
                        role.clone(),
                        FactScope::Global,
                        key.as_bytes().to_vec(),
                        value.clone(),
                    )));
                }
                if fact.id != consumer_id {
                    return Ok(ProjectionOutput::new());
                }
                let need = ContextNeed {
                    owner: fact.id,
                    role: role.clone(),
                    scope: FactScope::Global,
                    key: key.clone(),
                };
                let Some(payload) = context.payload_for(&need) else {
                    return Ok(ProjectionOutput::new().need(need));
                };
                assert_eq!(payload.id, producer_id);
                assert_eq!(&payload.scope, &producer_scope);
                assert_eq!(payload.timestamp, 41);
                assert_eq!(payload.bytes.as_slice(), value.as_slice());
                Ok(ProjectionOutput::new().intent(Intent::new(
                    IntentKind::new("ready").unwrap(),
                    fact.id,
                    b"ok".to_vec(),
                )))
            }
        });
        let first = drain_projection(&projector, &store, &[], None, 1)
            .expect("consumer parks on missing offer");

        assert!(first);
        submit_fact_to_db(&store, producer.clone()).expect("submit producer");
        let second =
            drain_projection(&projector, &store, &[], None, 3).expect("producer wakes consumer");

        assert!(second);
        assert_eq!(
            intent_payload_for(&store, "ready", &consumer.id),
            b"ok".to_vec()
        );
    }

    #[test]
    fn projection_drain_resolves_new_need_that_matches_existing_offer() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let target = Fact::new(FactScope::Global, 1, b"target".to_vec());
        let offered = Fact::new(FactScope::Global, 2, b"available".to_vec());
        submit_fact_to_db(&store, offered.clone()).expect("persist offer payload");
        submit_fact_to_db(&store, target.clone()).expect("persist target");
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
            value: offered.bytes.clone(),
        };
        crate::core::project_fact::context_db::insert_context_offer_for_test(&store, &offer)
            .expect("insert stored offer");

        let projector = need_until_payload(role, key, "ready", Some("premature"));
        let progress =
            drain_projection(&projector, &store, &[], None, 2).expect("drain projection");

        assert!(progress);
        assert_eq!(
            intent_payload_for(&store, "ready", &target.id),
            offered.id.to_vec()
        );
        let target_context = stored_context_for_owner(&store, &target.id).expect("target context");
        assert!(target_context.needs.is_empty());
        assert_eq!(pending_projection_count(&store, target.id), 0);
    }

    #[test]
    fn projection_drain_attaches_all_satisfied_context_when_later_need_wakes() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let target = Fact::new(FactScope::Global, 1, b"multi-stage-target".to_vec());
        let first_offer = Fact::new(FactScope::Global, 2, b"multi-stage-first".to_vec());
        let second_offer = Fact::new(FactScope::Global, 3, b"multi-stage-second".to_vec());
        submit_fact_to_db(&store, target.clone()).expect("submit target");

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

        assert!(first);
        assert_eq!(pending_projection_count(&store, target.id), 0);

        submit_fact_to_db(&store, first_offer.clone()).expect("submit first offer");
        let second =
            drain_projection(&projector, &store, &[], None, 2).expect("first offer wakes target");

        assert!(second);
        assert!(intent_payload_for_maybe(&store, "multi_stage_ready", &target.id).is_none());
        let staged_context = stored_context_for_owner(&store, &target.id).expect("target context");
        assert_eq!(staged_context.needs.len(), 2);

        submit_fact_to_db(&store, second_offer.clone()).expect("submit second offer");
        let third = drain_projection(&projector, &store, &[], None, 3)
            .expect("second offer wakes target with complete context");

        assert!(third);
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
    fn projection_drain_uses_context_attached_to_pending_queue() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let target = Fact::new(FactScope::Global, 1, b"queued-context-target".to_vec());
        let offered = Fact::new(FactScope::Global, 2, b"queued-context-payload".to_vec());
        submit_facts_to_db(&store, vec![target.clone(), offered.clone()]).expect("persist facts");
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
                    &ContextSetAdditions {
                        offers: vec![offer.clone()],
                        ..ContextSetAdditions::default()
                    },
                )
                .map_err(sqlite_string_error)?;
                delete_rows_by_owner_in_tx(tx, CONTEXT_NEEDS, offered.id)?;
                Ok(())
            })
            .expect("queue match then remove standing offer");

        assert_eq!(pending_projection_match_count(&store, target.id), 1);
        let projector = need_until_payload(role, key, "queued_context_ready", None);
        let progress =
            drain_projection(&projector, &store, &[], None, 1).expect("drain projection");

        assert!(progress);
        assert_eq!(
            intent_payload_for(&store, "queued_context_ready", &target.id),
            offered.id.to_vec()
        );
        assert_eq!(pending_projection_match_count(&store, target.id), 0);
    }

    #[test]
    fn incoming_fact_missing_context_is_retained_and_parked() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let parent = Fact::new(FactScope::Local, 1, b"ephemeral-need".to_vec());
        store
            .write_transaction(|tx| insert_incoming_fact_in_tx(tx, &parent))
            .expect("insert incoming fact");

        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([7; 32]);
        let projector = need_only(role.clone(), key.clone());
        let progress =
            drain_projection(&projector, &store, &[], None, 10).expect("incoming parks on needs");

        assert!(progress);
        assert!(incoming_fact_by_id(&store, &parent.id)
            .expect("load incoming")
            .is_none());
        assert!(retained_fact(&store, &parent.id)
            .expect("load retained incoming")
            .is_some());
        let context = stored_context_for_owner(&store, &parent.id).expect("parent context");
        assert_eq!(context.needs.len(), 1);
        assert!(context.offers.is_empty());
    }

    #[test]
    fn ephemeral_input_can_use_existing_durable_context() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let parent = Fact::new(FactScope::Local, 1, b"ephemeral-context".to_vec());
        let offered = Fact::new(FactScope::Global, 2, b"available".to_vec());
        submit_fact_to_db(&store, offered.clone()).expect("persist offer payload");
        store
            .conn()
            .execute(
                "DELETE FROM pending_projection WHERE owner = ?1",
                rusqlite::params![offered.id.as_slice()],
            )
            .expect("clear offered fact pending row");
        store
            .write_transaction(|tx| insert_incoming_fact_in_tx(tx, &parent))
            .expect("insert incoming fact");

        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([8; 32]);
        let offer = ContextOffer {
            owner: offered.id,
            role: role.clone(),
            scope: parent.scope.clone(),
            start_key: key.clone(),
            end_key: key.clone(),
            value: offered.bytes.clone(),
        };
        crate::core::project_fact::context_db::insert_context_offer_for_test(&store, &offer)
            .expect("insert stored offer");

        let projector = need_until_payload(role.clone(), key.clone(), "ephemeral_ready", None);
        let progress =
            drain_projection(&projector, &store, &[], None, 10).expect("drain projection");

        assert!(progress);
        assert!(incoming_fact_by_id(&store, &parent.id)
            .expect("load incoming")
            .is_none());
        assert!(retained_fact(&store, &parent.id)
            .expect("load retained incoming")
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
    fn ephemeral_input_queues_child_fact_for_projection() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let parent = Fact::new(FactScope::Local, 1, b"ephemeral-parent".to_vec());
        let child = Fact::new(FactScope::Global, 2, b"child-offer".to_vec());
        store
            .write_transaction(|tx| insert_incoming_fact_in_tx(tx, &parent))
            .expect("insert incoming fact");

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

        assert!(progress);
        assert!(incoming_fact_by_id(&store, &parent.id)
            .expect("load ephemeral")
            .is_none());
        assert_eq!(
            retained_fact(&store, &child.id)
                .expect("load child")
                .as_ref(),
            Some(&child)
        );
        let child_context = stored_context_for_owner(&store, &child.id).expect("child context");
        assert_eq!(child_context.offers.len(), 1);
        assert!(child_context.needs.is_empty());
    }

    #[test]
    fn projection_drain_isolates_a_failed_fact_without_rolling_back_previous_items() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let offered = Fact::new(FactScope::Global, 1, b"rollback-queue-offer".to_vec());
        let failing = Fact::new(FactScope::Global, 2, b"rollback-queue-fail".to_vec());
        assert_eq!(
            submit_facts_to_db(&store, vec![offered.clone(), failing.clone()])
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
        assert!(progress);
        assert_eq!(pending_projection_count(&store, offered.id), 0);
        assert!(context_edge_count(&store, offered.id) > 0);

        // Projector errors do not consume durable bytes. Core keeps the fact as
        // retained evidence and only clears this pending work marker.
        // projector-owned delete must be emitted as `purge_self`.
        assert_eq!(pending_projection_count(&store, failing.id), 0);
        assert!(retained_fact(&store, &failing.id)
            .expect("load failing fact")
            .is_some());
    }

    #[test]
    fn projection_drain_keeps_a_context_inconsistent_fact_as_evidence() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let offered = Fact::new(FactScope::Global, 1, b"inconsistent-offer".to_vec());
        let failing = Fact::new(FactScope::Global, 2, b"inconsistent-dependent".to_vec());
        assert_eq!(
            submit_facts_to_db(&store, vec![offered.clone(), failing.clone()])
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

        assert!(progress);
        assert_eq!(pending_projection_count(&store, offered.id), 0);

        // Projector errors do not let core infer a purge decision. The durable
        // bytes are retained and only the pending work marker is cleared.
        assert_eq!(pending_projection_count(&store, failing.id), 0);
        assert!(retained_fact(&store, &failing.id)
            .expect("load failing fact")
            .is_some());
    }

    #[test]
    fn child_fact_projection_error_isolated_after_parent_commits() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let parent = Fact::new(FactScope::Local, 1, b"ephemeral-parent".to_vec());
        let child = Fact::new(FactScope::Global, 2, b"child-error".to_vec());
        store
            .write_transaction(|tx| insert_incoming_fact_in_tx(tx, &parent))
            .expect("insert incoming fact");

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

        assert!(progress);
        assert!(incoming_fact_by_id(&store, &parent.id)
            .expect("load ephemeral")
            .is_none());
        assert_eq!(pending_projection_count(&store, child.id), 0);
        assert!(retained_fact(&store, &child.id)
            .expect("load child")
            .is_some());
    }

    #[test]
    fn projection_storage_mismatch_consumes_pending_without_committing_projector_effects() {
        VERSION_GUARD_PROJECTOR_CALLS.store(0, Ordering::SeqCst);
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        let fact = Fact::new(FactScope::Global, 1, vec![201]);
        submit_fact_to_db(&store, fact.clone()).expect("submit pending fact");

        let consumed = crate::core::project_fact::project_one(
            &store,
            &RouterProjector::new(VERSION_GUARD_ROUTES, &[]),
            ProjectionSource::Durable,
            &[],
            &[],
            None,
        )
        .expect("storage mismatch should consume stale-version projection input");

        assert!(consumed);
        assert_eq!(VERSION_GUARD_PROJECTOR_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(
            pending_projection_count(&store, fact.id),
            0,
            "stale-version projection input should be consumed"
        );
        let stored = stored_context_for_owner(&store, &fact.id).expect("stored context");
        assert!(
            stored.needs.is_empty() && stored.offers.is_empty(),
            "stale-version projector effects must not publish standing context"
        );
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
        let offer = ContextOffer {
            owner: [2; 32],
            role,
            scope: FactScope::Global,
            start_key: key.clone(),
            end_key: key,
            value: Vec::new(),
        };

        let next = run_projection(&projector, &fact, ProjectionContext::new(vec![offer]))
            .expect("projection with context");

        assert!(next.projected_context.needs.is_empty());
        assert_eq!(next.runtime_effects.intents.len(), 1);
        assert_eq!(next.runtime_effects.intents[0].kind.as_str(), "followup");
    }

    #[test]
    fn projection_drain_resolves_exact_need_that_matches_existing_range_offer() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let target = Fact::new(FactScope::Global, 1, b"target".to_vec());
        let offered = Fact::new(FactScope::Global, 2, b"custom".to_vec());
        submit_fact_to_db(&store, offered.clone()).expect("persist offer payload");
        submit_fact_to_db(&store, target.clone()).expect("persist target");
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
            value: offered.bytes.clone(),
        };
        crate::core::project_fact::context_db::insert_context_offer_for_test(&store, &offer)
            .expect("insert stored offer");

        let projector = need_until_payload(role, key, "ready", Some("premature"));
        let progress =
            drain_projection(&projector, &store, &[], None, 2).expect("drain projection");

        assert!(progress);
        assert_eq!(
            intent_payload_for(&store, "ready", &target.id),
            offered.id.to_vec()
        );
    }

    #[test]
    fn projection_commit_wakes_readded_need_against_current_context() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let target = Fact::new(FactScope::Global, 1, b"readded-need-target".to_vec());
        let offered = Fact::new(FactScope::Global, 2, b"readded-need-offer".to_vec());
        submit_fact_to_db(&store, offered.clone()).expect("persist offer payload");
        submit_fact_to_db(&store, target.clone()).expect("persist target");
        store
            .conn()
            .execute(
                "DELETE FROM pending_projection WHERE owner = ?1",
                rusqlite::params![offered.id.as_slice()],
            )
            .expect("clear offered fact pending row");

        let role = Role::new("readded_need").unwrap();
        let key = ContextKey::from_bytes(b"same-need");
        let projector = ReaddedNeedProjector {
            target_id: target.id,
            role: role.clone(),
            key: key.clone(),
            step: Cell::new(0),
        };

        drain_projection(&projector, &store, &[], None, 1).expect("park on initial need");
        assert_eq!(
            stored_context_for_owner(&store, &target.id)
                .expect("initial context")
                .needs
                .len(),
            1
        );

        store
            .write_transaction(|tx| insert_pending_owner_in_tx(tx, target.id).map(|_| ()))
            .expect("queue target for need removal");
        drain_projection(&projector, &store, &[], None, 1).expect("remove initial need");
        assert!(stored_context_for_owner(&store, &target.id)
            .expect("removed context")
            .needs
            .is_empty());

        let offer = offer_for(&offered, &role, &key);
        crate::core::project_fact::context_db::insert_context_offer_for_test(&store, &offer)
            .expect("insert offer after need removal");
        store
            .write_transaction(|tx| insert_pending_owner_in_tx(tx, target.id).map(|_| ()))
            .expect("queue target for need re-add");

        let progress =
            drain_projection(&projector, &store, &[], None, 2).expect("re-added need wakes");

        assert!(progress);
        assert_eq!(
            intent_payload_for(&store, "readded_ready", &target.id),
            offered.id.to_vec()
        );
        assert_eq!(pending_projection_count(&store, target.id), 0);
    }

    #[test]
    fn projection_drain_can_keep_reemitted_need_after_it_matches() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let target = Fact::new(FactScope::Global, 1, b"watcher".to_vec());
        let offered = Fact::new(FactScope::Global, 2, b"watched".to_vec());
        submit_fact_to_db(&store, offered.clone()).expect("persist offer payload");
        submit_fact_to_db(&store, target.clone()).expect("persist target");
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
            value: b"watched".to_vec(),
        };
        crate::core::project_fact::context_db::insert_context_offer_for_test(&store, &offer)
            .expect("insert stored offer");

        let projector = reemitted_need(role, key, "observed");
        let progress =
            drain_projection(&projector, &store, &[], None, 2).expect("drain projection");

        assert!(progress);
        assert_eq!(
            intent_payload_for(&store, "observed", &target.id),
            b"watched".to_vec()
        );
        let target_context = stored_context_for_owner(&store, &target.id).expect("target context");
        assert_eq!(target_context.needs.len(), 1);
        assert_eq!(pending_projection_count(&store, target.id), 0);
    }

    #[test]
    fn projection_commit_keeps_existing_offer_when_owner_reprojects_without_it() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let fact = Fact::new(FactScope::Global, 1, b"stored-offer-evidence".to_vec());
        submit_fact_to_db(&store, fact.clone()).expect("persist fact");

        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([5; 32]);
        let offer = offer_for(&fact, &role, &key);
        crate::core::project_fact::context_db::insert_context_offer_for_test(&store, &offer)
            .expect("insert old offer");

        let projector = test_projector(|_fact, _context| Ok(ProjectionOutput::new()));
        let progress = drain_projection(&projector, &store, &[], None, 1)
            .expect("drain projection without re-emitting old offer");

        assert!(progress);
        let context = stored_context_for_owner(&store, &fact.id).expect("stored context");
        assert!(context.needs.is_empty());
        assert_eq!(context.offers, vec![offer]);
    }

    #[test]
    fn child_fact_parking_counts_as_successful_parent_projection() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let parent = Fact::new(FactScope::Local, 1, b"ephemeral-parent".to_vec());
        let child = Fact::new(FactScope::Global, 2, b"child-need".to_vec());
        store
            .write_transaction(|tx| insert_incoming_fact_in_tx(tx, &parent))
            .expect("insert incoming fact");

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

        assert!(progress);
        assert!(incoming_fact_by_id(&store, &parent.id)
            .expect("load ephemeral")
            .is_none());
        assert!(retained_fact(&store, &child.id)
            .expect("load child")
            .is_some());
        let child_context = stored_context_for_owner(&store, &child.id).expect("child context");
        assert_eq!(child_context.needs.len(), 1);
        assert!(child_context.offers.is_empty());
    }

    #[test]
    fn ephemeral_input_cannot_emit_effects_while_transient_needs_remain() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let parent = Fact::new(FactScope::Local, 1, b"ephemeral-partial".to_vec());
        store
            .write_transaction(|tx| insert_incoming_fact_in_tx(tx, &parent))
            .expect("insert incoming fact");

        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([9; 32]);
        let projector = test_projector(move |fact, _context| {
            Ok(ProjectionOutput::new()
                .drop_incoming()
                .need(need_for(fact, &role, &key))
                .intent(Intent::new(
                    IntentKind::new("ephemeral_partial").unwrap(),
                    fact.id,
                    Vec::new(),
                )))
        });
        let err = drain_projection(&projector, &store, &[], None, 10)
            .expect_err("dropped incoming facts cannot partially succeed with unresolved probes");

        assert!(err.contains("transient needs remain"), "{err}");
        assert!(incoming_fact_by_id(&store, &parent.id)
            .expect("load incoming")
            .is_some());
        let context = stored_context_for_owner(&store, &parent.id).expect("parent context");
        assert!(context.needs.is_empty());
        assert!(context.offers.is_empty());
    }

    #[test]
    fn ephemeral_input_cannot_emit_durable_offers() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let parent = Fact::new(FactScope::Local, 1, b"ephemeral-offer".to_vec());
        store
            .write_transaction(|tx| insert_incoming_fact_in_tx(tx, &parent))
            .expect("insert incoming fact");

        let role = Role::new("ephemeral_offer").unwrap();
        let projector = test_projector(move |fact, _context| {
            let key = ContextKey::from_bytes(fact.id);
            Ok(ProjectionOutput::new()
                .drop_incoming()
                .offer(offer_for(fact, &role, &key)))
        });
        let err = drain_projection(&projector, &store, &[], None, 10)
            .expect_err("dropped incoming offers should fail");

        assert!(err.contains("dropped incoming fact cannot emit durable offers"));
        assert!(incoming_fact_by_id(&store, &parent.id)
            .expect("load incoming")
            .is_some());
    }

    #[test]
    fn projection_evaluation_does_not_clear_rejected_durable_pending_work() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let fact = Fact::new(FactScope::Global, 1, b"durable reject".to_vec());
        submit_fact_to_db(&store, fact.clone()).expect("submit pending fact");
        let projector = test_projector(|_fact: &Fact, _context: &ProjectionContext| {
            Err("projector rejected durable fact".to_string())
        });

        let input = expect_loaded(
            load_one_projection_input(&store, ProjectionSource::Durable)
                .expect("load projection input"),
        );
        let outcome = evaluate_loaded_projection_input(&projector, input, test_effect_policy(&[]))
            .expect("evaluate projection");

        assert!(matches!(
            outcome,
            ProjectionOutcome::RetireRejectedInput {
                source: ProjectionSource::Durable,
                fact_id
            } if fact_id == fact.id
        ));
        assert_eq!(pending_projection_count(&store, fact.id), 1);
        assert!(retained_fact(&store, &fact.id)
            .expect("load retained fact")
            .is_some());

        commit_projection_effects(&store, &outcome, test_effect_policy(&[]))
            .expect("commit rejection");

        assert_eq!(pending_projection_count(&store, fact.id), 0);
        assert!(retained_fact(&store, &fact.id)
            .expect("load retained fact")
            .is_some());
    }

    #[test]
    fn projection_evaluation_does_not_delete_rejected_incoming_input() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let fact = Fact::new(FactScope::Local, 1, b"incoming reject".to_vec());
        store
            .write_transaction(|tx| insert_incoming_fact_in_tx(tx, &fact))
            .expect("insert incoming fact");
        let projector = test_projector(|_fact: &Fact, _context: &ProjectionContext| {
            Err("projector rejected incoming fact".to_string())
        });

        let input = expect_loaded(
            load_one_projection_input(&store, ProjectionSource::Incoming)
                .expect("load projection input"),
        );
        let outcome = evaluate_loaded_projection_input(&projector, input, test_effect_policy(&[]))
            .expect("evaluate projection");

        assert!(matches!(
            outcome,
            ProjectionOutcome::RetireRejectedInput {
                source: ProjectionSource::Incoming,
                fact_id
            } if fact_id == fact.id
        ));
        assert!(incoming_fact_by_id(&store, &fact.id)
            .expect("load incoming fact")
            .is_some());

        commit_projection_effects(&store, &outcome, test_effect_policy(&[]))
            .expect("commit rejection");

        assert!(incoming_fact_by_id(&store, &fact.id)
            .expect("load incoming fact")
            .is_none());
    }

    #[test]
    fn projection_rejects_unregistered_intent_output() {
        let fact = Fact::new(FactScope::Global, 1, b"unknown intent".to_vec());
        let projector = test_projector(|_fact: &Fact, _context: &ProjectionContext| {
            Ok(ProjectionOutput::new().intent(Intent::new(
                IntentKind::new("unknown_followup").expect("intent kind"),
                b"child".to_vec(),
                Vec::new(),
            )))
        });

        let err = run_projection_with_registered_intents(
            &projector,
            &fact,
            ProjectionContext::new(Vec::new()),
            &[],
        )
        .expect_err("unregistered intent output should fail validation");

        assert!(
            err.contains("intent kind unknown_followup is not registered"),
            "{err}"
        );
    }

    #[test]
    fn projection_prepare_records_only_projector_output_context() {
        let fact = Fact::new(FactScope::Global, 1, b"stable".to_vec());
        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([9; 32]);
        let projector = need_until_offer(role, key, IntentKind::new("followup").unwrap());

        let projection = run_projection(&projector, &fact, ProjectionContext::new(Vec::new()))
            .expect("prepare projection");

        assert_eq!(projection.projected_context.needs.len(), 1);
        assert!(projection.projected_context.offers.is_empty());
        assert!(projection.runtime_effects.intents.is_empty());
    }

    #[test]
    fn projection_run_allows_self_purge() {
        let fact = Fact::new(FactScope::Global, 1, b"owned".to_vec());
        let projector = test_projector(|fact: &Fact, _context: &ProjectionContext| {
            Ok(ProjectionOutput::new().purge_self(fact.id))
        });

        let run = run_projection(&projector, &fact, ProjectionContext::new(Vec::new()))
            .expect("projection should allow self purge");

        assert_eq!(run.runtime_effects.purged_facts, vec![fact.id]);
    }

    #[test]
    fn projection_run_rejects_purge_owned_by_another_fact() {
        let fact = Fact::new(FactScope::Global, 1, b"owned".to_vec());
        let projector = test_projector(|_fact: &Fact, _context: &ProjectionContext| {
            Ok(ProjectionOutput::new().purge_self([9; 32]))
        });

        let err = run_projection(&projector, &fact, ProjectionContext::new(Vec::new()))
            .expect_err("projection should reject foreign purge owner");

        assert!(err.contains("projector tried to purge fact"));
    }

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
                value: Vec::new(),
            }))
        });

        let err = run_projection(&projector, &fact, ProjectionContext::new(Vec::new()))
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
                key: ContextKey::from_bytes(fact.id),
            }))
        });

        let err = run_projection(&projector, &fact, ProjectionContext::new(Vec::new()))
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

        let err = run_projection(&projector, &fact, ProjectionContext::new(Vec::new()))
            .expect_err("projection should reject foreign time-wake owner");

        assert!(err.contains("projector emitted time wake"));
    }

    #[test]
    fn incoming_fact_origin_metadata_is_volatile_after_fact_is_retained() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let parent = Fact::new(FactScope::Local, 1, b"ephemeral-origin".to_vec());
        let metadata = IncomingMetadata {
            origin_addr: b"127.0.0.1:41001".to_vec(),
            received_at_local_ms: 1_700_000_222,
        };
        store
            .write_transaction(|tx| insert_network_incoming_fact_in_tx(tx, &parent, &metadata))
            .expect("insert incoming fact with metadata");
        let incoming = load_pending_fact(
            &store,
            ProjectionSource::Incoming,
            parent.id,
            ProjectionMode::Normal,
        )
        .expect("load incoming fact")
        .expect("incoming fact should load");
        assert_eq!(incoming.pending_inputs.incoming_metadata(), Some(&metadata));

        let role = Role::new("exact").unwrap();
        let key = ContextKey::from_bytes([17; 32]);
        let projector = need_only(role, key);
        let progress =
            drain_projection(&projector, &store, &[], None, 10).expect("incoming parks on needs");

        assert!(progress);
        assert!(incoming_fact_by_id(&store, &parent.id)
            .expect("load incoming")
            .is_none());
        let input = load_pending_fact(
            &store,
            ProjectionSource::Durable,
            parent.id,
            ProjectionMode::Normal,
        )
        .expect("load parked fact")
        .expect("parked fact should load");
        assert_eq!(input.pending_inputs.incoming_metadata(), None);
    }

    #[test]
    fn emitted_incoming_fact_can_preserve_origin_metadata() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let parent = Fact::new(FactScope::Local, 1, b"metadata-parent".to_vec());
        let child = Fact::new(FactScope::Global, 2, b"metadata-child".to_vec());
        let metadata = IncomingMetadata {
            origin_addr: b"127.0.0.1:41001".to_vec(),
            received_at_local_ms: 1_700_000_333,
        };
        store
            .write_transaction(|tx| insert_network_incoming_fact_in_tx(tx, &parent, &metadata))
            .expect("insert incoming fact with metadata");

        let child_for_projector = child.clone();
        let projector = test_projector(move |_fact, context| {
            let metadata = context
                .incoming_metadata()
                .expect("incoming metadata")
                .clone();
            Ok(ProjectionOutput::new()
                .drop_incoming()
                .incoming_fact_with_metadata(child_for_projector.clone(), metadata))
        });
        assert!(crate::core::project_fact::project_one(
            &store,
            &projector,
            ProjectionSource::Incoming,
            &[],
            TEST_REGISTERED_INTENT_KINDS,
            None,
        )
        .expect("project parent"));

        let child_input = load_pending_fact(
            &store,
            ProjectionSource::Incoming,
            child.id,
            ProjectionMode::Normal,
        )
        .expect("load child")
        .expect("child should be staged as incoming");
        assert_eq!(
            child_input.pending_inputs.incoming_metadata(),
            Some(&metadata)
        );
    }

    #[test]
    fn projection_commit_records_projected_at_with_origin_receive_time() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let parent = Fact::new(FactScope::Local, 42, b"timed-parent".to_vec());
        let metadata = IncomingMetadata {
            origin_addr: b"127.0.0.1:41001".to_vec(),
            received_at_local_ms: 1_700_000_444,
        };
        store
            .write_transaction(|tx| insert_network_incoming_fact_in_tx(tx, &parent, &metadata))
            .expect("insert incoming fact with metadata");

        let before = queue_now_ms().expect("clock before projection");
        let projector =
            test_projector(|_fact, _context| Ok(ProjectionOutput::new().drop_incoming()));
        assert!(crate::core::project_fact::project_one(
            &store,
            &projector,
            ProjectionSource::Incoming,
            &[],
            TEST_REGISTERED_INTENT_KINDS,
            None,
        )
        .expect("project parent"));

        let (
            fact_type,
            source,
            received_at,
            origin_received_at,
            input_staged_at,
            first_projected_at,
            projected_at,
            projection_count,
            retained,
        ): (
            i64,
            String,
            i64,
            Option<i64>,
            Option<i64>,
            i64,
            i64,
            i64,
            i64,
        ) = store
            .conn()
            .query_row(
                "SELECT
                    fact_type,
                    source,
                    received_at,
                    origin_received_at,
                    input_staged_at,
                    first_projected_at,
                    projected_at,
                    projection_count,
                    retained
                 FROM projection_timings
                 WHERE fact_id = ?1",
                params![parent.id.as_slice()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                        row.get(8)?,
                    ))
                },
            )
            .expect("load projection timing");

        assert_eq!(fact_type, b't' as i64);
        assert_eq!(source, "incoming");
        assert_eq!(received_at, 42);
        assert_eq!(
            origin_received_at,
            Some(metadata.received_at_local_ms as i64)
        );
        assert!(
            input_staged_at.is_some_and(|staged_at| staged_at <= projected_at),
            "input_staged_at {input_staged_at:?} should exist before projected_at {projected_at}"
        );
        assert!(
            first_projected_at >= before,
            "first_projected_at {first_projected_at} should be at or after {before}"
        );
        assert!(
            projected_at >= before,
            "projected_at {projected_at} should be at or after {before}"
        );
        assert_eq!(first_projected_at, projected_at);
        assert_eq!(projection_count, 1);
        assert_eq!(retained, 0);
    }

    #[test]
    fn projection_timing_preserves_first_projected_at_across_reprojection() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let fact = Fact::new(FactScope::Global, 42, b"timed-reprojection".to_vec());
        submit_fact_to_db(&store, fact.clone()).expect("persist fact");

        let projector = test_projector(|_fact, _context| Ok(ProjectionOutput::new()));
        assert!(crate::core::project_fact::project_one(
            &store,
            &projector,
            ProjectionSource::Durable,
            &[],
            TEST_REGISTERED_INTENT_KINDS,
            None,
        )
        .expect("first projection"));

        let first: (i64, i64, i64) = store
            .conn()
            .query_row(
                "SELECT first_projected_at, projected_at, projection_count
                 FROM projection_timings
                 WHERE fact_id = ?1",
                params![fact.id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("load first timing");

        insert_pending_owner_with_mode_in_tx(&store, fact.id, ProjectionMode::Normal)
            .expect("requeue fact");
        assert!(crate::core::project_fact::project_one(
            &store,
            &projector,
            ProjectionSource::Durable,
            &[],
            TEST_REGISTERED_INTENT_KINDS,
            None,
        )
        .expect("second projection"));

        let second: (i64, i64, i64) = store
            .conn()
            .query_row(
                "SELECT first_projected_at, projected_at, projection_count
                 FROM projection_timings
                 WHERE fact_id = ?1",
                params![fact.id.as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .expect("load second timing");

        assert_eq!(second.0, first.0);
        assert!(second.1 >= first.1);
        assert_eq!(second.2, 2);
    }

    #[test]
    fn exact_context_lookup_plan_uses_exact_key_index() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");

        let plan = query_plan_text(
            &store,
            r#"
            EXPLAIN QUERY PLAN
            SELECT owner, role, scope_key, key
    FROM context_needs
    WHERE role = 'exact_plan'
      AND scope_key = x'01'
      AND key = x'02'
            ORDER BY owner, key
            "#,
        );

        assert!(
            plan.contains("context_needs_by_key"),
            "exact lookup should use the exact key index:\n{plan}"
        );
        assert!(
            !plan.contains("context_range_offers"),
            "exact need lookup should not touch range offer rows:\n{plan}"
        );
    }

    fn drain_projection(
        projector: &impl Projector,
        store: &Db,
        allowed_tables: &[TableName],
        fact_admission: Option<FactAdmissionFn>,
        limit: usize,
    ) -> Result<bool, String> {
        let mut progressed = false;
        for _ in 0..limit {
            let mut step = crate::core::project_fact::project_one(
                store,
                projector,
                ProjectionSource::Durable,
                allowed_tables,
                TEST_REGISTERED_INTENT_KINDS,
                fact_admission,
            )?;
            if !step {
                step = crate::core::project_fact::project_one(
                    store,
                    projector,
                    ProjectionSource::Incoming,
                    allowed_tables,
                    TEST_REGISTERED_INTENT_KINDS,
                    fact_admission,
                )?;
            }
            if !step {
                break;
            }
            progressed = true;
        }
        Ok(progressed)
    }

    fn incoming_fact_by_id(store: &Db, id: &FactId) -> Result<Option<Fact>, String> {
        incoming_fact_by_id_in_tx(store, id).map_err(|err| format!("load incoming fact: {err}"))
    }

    fn intent_payload_for(store: &Db, kind: &str, key: &FactId) -> Vec<u8> {
        intent_payload_for_maybe(store, kind, key).expect("load intent payload")
    }

    fn intent_payload_for_maybe(store: &Db, kind: &str, key: &FactId) -> Option<Vec<u8>> {
        store
            .conn()
            .query_row(
                "SELECT payload FROM intents WHERE kind = ?1 AND intent_key = ?2 ORDER BY rowid LIMIT 1",
                rusqlite::params![kind, key.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .expect("load optional intent payload")
    }

    fn pending_projection_count(store: &Db, owner: FactId) -> i64 {
        store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pending_projection WHERE owner = ?1",
                rusqlite::params![owner.as_slice()],
                |row| row.get(0),
            )
            .expect("count pending projection")
    }

    fn pending_projection_match_count(store: &Db, owner: FactId) -> i64 {
        store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pending_projection_matches WHERE owner = ?1",
                rusqlite::params![owner.as_slice()],
                |row| row.get(0),
            )
            .expect("count pending projection matches")
    }

    fn context_edge_count(store: &Db, owner: FactId) -> i64 {
        context_edge_table_count(store, CONTEXT_NEEDS, owner)
            + context_edge_table_count(store, CONTEXT_EXACT_OFFERS, owner)
            + context_edge_table_count(store, CONTEXT_RANGE_OFFERS, owner)
    }

    fn context_edge_table_count(store: &Db, table: TableName, owner: FactId) -> i64 {
        let table = quoted_table_name(table).expect("quote table");
        store
            .conn()
            .query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE owner = ?1"),
                rusqlite::params![owner.as_slice()],
                |row| row.get(0),
            )
            .expect("count context edge rows")
    }

    fn query_plan_text(store: &Db, sql: &str) -> String {
        let mut stmt = store.conn().prepare(sql).expect("prepare query plan");
        stmt.query_map([], |row| row.get::<_, String>(3))
            .expect("run query plan")
            .collect::<rusqlite::Result<Vec<_>>>()
            .expect("collect query plan")
            .join("\n")
    }

    fn need_for(fact: &Fact, role: &Role, key: &ContextKey) -> ContextNeed {
        ContextNeed {
            owner: fact.id,
            role: role.clone(),
            scope: fact.scope.clone(),
            key: key.clone(),
        }
    }

    fn offer_for(fact: &Fact, role: &Role, key: &ContextKey) -> ContextOffer {
        ContextOffer {
            owner: fact.id,
            role: role.clone(),
            scope: fact.scope.clone(),
            start_key: key.clone(),
            end_key: key.clone(),
            value: Vec::new(),
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

    fn reemitted_need(role: Role, key: ContextKey, intent_kind: &'static str) -> impl Projector {
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

    struct SemanticOfferProjector {
        producer_id: FactId,
        consumer_id: FactId,
        role: Role,
        key: ContextKey,
        offered_value: Vec<u8>,
    }

    impl Projector for SemanticOfferProjector {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            if fact.id == self.producer_id {
                let decoded =
                    decode_v0_author_fact(fact.body()).ok_or("unknown author fact layout")?;
                return Ok(ProjectionOutput::new().offer(ContextOffer::for_key_value(
                    fact.id,
                    self.role.clone(),
                    fact.scope.clone(),
                    self.key.as_bytes().to_vec(),
                    decoded,
                )));
            }

            if fact.id != self.consumer_id {
                return Ok(ProjectionOutput::new());
            }

            let need = need_for(fact, &self.role, &self.key);
            let Some(value) = context.value_for(&need) else {
                return Ok(ProjectionOutput::new().need(need));
            };
            if value != self.offered_value.as_slice() {
                return Err("consumer received unexpected semantic offer value".to_string());
            }
            if context
                .payload_for(&need)
                .is_some_and(|payload| payload.bytes != value)
            {
                return Err("legacy payload helper did not expose offer value".to_string());
            }
            Ok(ProjectionOutput::new().intent(Intent::new(
                IntentKind::new("semantic_ready").unwrap(),
                fact.id,
                value.to_vec(),
            )))
        }
    }

    fn decode_v0_author_fact(bytes: &[u8]) -> Option<Vec<u8>> {
        bytes
            .strip_prefix(b"author-v0|profile:ada|")
            .map(|value| value.to_vec())
    }

    fn decode_v1_author_fact(bytes: &[u8]) -> Result<Vec<u8>, String> {
        bytes
            .strip_prefix(b"author-v1\0")
            .map(|value| value.to_vec())
            .ok_or_else(|| "not a v1 author fact".to_string())
    }

    struct ReaddedNeedProjector {
        target_id: FactId,
        role: Role,
        key: ContextKey,
        step: Cell<usize>,
    }

    impl Projector for ReaddedNeedProjector {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            if fact.id != self.target_id {
                return Ok(ProjectionOutput::new());
            }

            let need = need_for(fact, &self.role, &self.key);
            let step = self.step.get();
            self.step.set(step + 1);
            match step {
                0 => Ok(ProjectionOutput::new().need(need)),
                1 => Ok(ProjectionOutput::new()),
                _ => {
                    if let Some(payload) = context.payload_for(&need) {
                        Ok(ProjectionOutput::new().intent(Intent::new(
                            IntentKind::new("readded_ready").unwrap(),
                            fact.id,
                            payload.id,
                        )))
                    } else {
                        Ok(ProjectionOutput::new().need(need))
                    }
                }
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

// -----------------------------------------------------------------------------
// Unit Tests
// -----------------------------------------------------------------------------
//
// Unit coverage of the building blocks `contract_tests` composes, ordered
// most-central first: content-addressed fact identity and the purge/delete
// derived-row cleanup invariant lead, queue selection ordering follows, and the
// `ProjectionOutput`/`ProjectionContext` value-type checks and route metadata
// come last.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{scope_key, ContextKey, ContextNeed, ContextOffer, Role};
    use crate::core::effects::StorageRequirement;
    use crate::core::facts::{Fact, FactId, FactScope};
    use crate::core::schema::CORE_SCHEMA_SOURCE;

    #[test]
    fn duplicate_fact_bytes_are_idempotent_even_with_different_local_admissions() {
        let db = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        let first = Fact::new(FactScope::Global, 1, b"same fact bytes".to_vec());
        let duplicate = Fact::new(FactScope::Local, 2, first.bytes.clone());
        assert_eq!(first.id, duplicate.id);

        db.write_transaction(|tx| {
            assert!(insert_fact_and_pending_in_tx(tx, &first)?);
            assert!(!insert_fact_and_pending_in_tx(tx, &duplicate)?);
            Ok(())
        })
        .expect("insert duplicate fact bytes");

        assert_eq!(
            retained_fact(&db, &first.id).expect("load fact"),
            Some(first)
        );
    }

    #[test]
    fn purge_fact_clears_owner_keyed_and_offer_keyed_runtime_rows() {
        let db = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        let fact = Fact::new(FactScope::Local, 1, b"retained cleanup".to_vec());
        let other = Fact::new(FactScope::Local, 2, b"other retained".to_vec());

        db.write_transaction(|tx| {
            insert_retained_fact_in_tx(tx, &fact)?;
            seed_owner_keyed_fact_rows(tx, fact.id, other.id)?;
            seed_pending_match(tx, other.id, fact.id)
        })
        .expect("seed retained owner rows");
        assert_owner_keyed_fact_rows(&db, fact.id, 1);
        assert_eq!(pending_match_offer_count(&db, fact.id), 1);

        assert!(db
            .write_transaction(|tx| purge_fact_in_tx(tx, fact.id))
            .expect("purge fact"));

        assert!(fact_bytes_by_id_in_tx(&db, &fact.id)
            .expect("load retained fact")
            .is_none());
        assert_owner_keyed_fact_rows(&db, fact.id, 0);
        assert_eq!(pending_match_offer_count(&db, fact.id), 0);
    }

    #[test]
    fn delete_incoming_fact_clears_owner_keyed_runtime_rows() {
        let db = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        let fact = Fact::new(FactScope::Local, 1, b"incoming cleanup".to_vec());
        let offer = Fact::new(FactScope::Local, 2, b"incoming offer".to_vec());

        db.write_transaction(|tx| {
            insert_incoming_fact_in_tx(tx, &fact)?;
            seed_owner_keyed_fact_rows(tx, fact.id, offer.id)
        })
        .expect("seed incoming owner rows");
        assert_owner_keyed_fact_rows(&db, fact.id, 1);

        assert!(db
            .write_transaction(|tx| delete_incoming_fact_in_tx(tx, fact.id))
            .expect("delete incoming fact"));

        assert!(incoming_fact_by_id_in_tx(&db, &fact.id)
            .expect("load incoming fact")
            .is_none());
        assert_owner_keyed_fact_rows(&db, fact.id, 0);
    }

    #[test]
    fn priority_pending_projection_runs_before_older_normal_work() {
        let db = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        let normal = Fact::new(FactScope::Global, 1, b"normal pending".to_vec());
        let priority = Fact::new(FactScope::Local, 2, b"priority pending".to_vec());

        db.write_transaction(|tx| {
            assert!(insert_fact_and_pending_with_mode_in_tx(
                tx,
                &normal,
                ProjectionMode::Normal
            )?);
            assert!(insert_priority_fact_and_pending_with_mode_in_tx(
                tx,
                &priority,
                ProjectionMode::Normal
            )?);
            Ok(())
        })
        .expect("insert pending facts");

        assert_eq!(
            next_durable_projection_item(&db)
                .expect("next pending")
                .expect("pending item")
                .owner,
            priority.id
        );
    }

    #[test]
    fn next_incoming_projection_item_reads_oldest_incoming_fact_without_context_filter() {
        let db = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        let oldest = Fact::new(FactScope::Local, 0, b"oldest incoming".to_vec());
        let newer = Fact::new(FactScope::Local, 1, b"newer incoming".to_vec());

        db.write_transaction(|tx| {
            insert_incoming_fact_in_tx(tx, &oldest)?;
            insert_incoming_fact_in_tx(tx, &newer)?;
            insert_context_need_in_tx(
                tx,
                &ContextNeed::for_key(
                    oldest.id,
                    "incoming_context",
                    FactScope::Local,
                    b"a".to_vec(),
                ),
            )?;
            Ok(())
        })
        .expect("seed incoming facts");

        assert_eq!(
            next_incoming_projection_item(&db)
                .expect("next incoming")
                .map(|item| item.owner),
            Some(oldest.id)
        );
    }

    #[test]
    fn projection_context_returns_matched_payloads_by_need() {
        let role = Role::new("exact").unwrap();
        let need_a = ContextNeed {
            owner: [1; 32],
            role: role.clone(),
            scope: FactScope::Global,
            key: ContextKey::from_bytes([10; 32]),
        };
        let need_b = ContextNeed {
            owner: [2; 32],
            role: role.clone(),
            scope: FactScope::Global,
            key: ContextKey::from_bytes([20; 32]),
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
    fn projection_output_exposes_normalized_replacement_context() {
        let id = [1; 32];
        let role = Role::new("exact").unwrap();
        let need = ContextNeed {
            owner: id,
            role,
            scope: FactScope::Global,
            key: ContextKey::from_bytes([2; 32]),
        };
        let output = ProjectionOutput::new()
            .need(need.clone())
            .need(need.clone());

        assert_eq!(output.context_set().needs, vec![need]);
    }

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
                key: key.clone(),
            })
            .offer(ContextOffer {
                owner: id,
                role,
                scope: FactScope::Global,
                start_key: key.clone(),
                end_key: key,
                value: Vec::new(),
            });

        assert_eq!(output.needs.len(), 1);
        assert_eq!(output.offers.len(), 1);
        assert!(output.effects.intents.is_empty());
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
            storage_requirement: StorageRequirement::MaintenanceBypass,
            projector_info: FactProjectorInfo::projector("ModelProjector"),
        };

        assert_eq!(route.projector_info.project, "ModelProjector");
        let output = (route.projector)(
            &Fact::new(FactScope::Global, 1, vec![200, 5]),
            &ProjectionContext::default(),
        )
        .expect("route projection");
        assert_eq!(output.offers.len(), 1);
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
                start_key: need.key.clone(),
                end_key: need.key.clone(),
                value: payload.bytes.clone(),
            },
            need,
            payload,
        }
    }

    fn seed_owner_keyed_fact_rows(
        store: &Db,
        owner: FactId,
        offer_owner: FactId,
    ) -> rusqlite::Result<()> {
        insert_context_need_in_tx(
            store,
            &ContextNeed::for_key(owner, "cleanup_role", FactScope::Local, b"a".to_vec()),
        )?;
        store.conn().execute(
            "INSERT INTO time_wakes (timeline, at, owner)
             VALUES ('cleanup_timeline', 1, ?1)",
            params![owner.as_slice()],
        )?;
        store.conn().execute(
            "INSERT INTO pending_time_ranges
                (owner, timeline, has_start, start_exclusive, end_inclusive)
             VALUES (?1, 'cleanup_timeline', 0, 0, 1)",
            params![owner.as_slice()],
        )?;
        store.conn().execute(
            "INSERT INTO pending_projection (owner, queued_at)
             VALUES (?1, 0)",
            params![owner.as_slice()],
        )?;
        seed_pending_match(store, owner, offer_owner)
    }

    fn seed_pending_match(store: &Db, owner: FactId, offer_owner: FactId) -> rusqlite::Result<()> {
        let offer = cleanup_offer(offer_owner);
        insert_context_offer_in_tx(store, &offer)?;
        let offer_id = offer.id();
        let scope_key = scope_key(&FactScope::Local);
        store.conn().execute(
            "INSERT INTO pending_projection_matches
                (owner, need_role, need_scope_key, need_key, offer_id)
             VALUES (?1, 'cleanup_role', ?2, ?3, ?4)",
            params![
                owner.as_slice(),
                scope_key.as_slice(),
                b"a".as_slice(),
                offer_id.as_slice()
            ],
        )?;
        Ok(())
    }

    fn cleanup_offer(owner: FactId) -> ContextOffer {
        ContextOffer::range_value(
            owner,
            "cleanup_role",
            FactScope::Local,
            b"a".to_vec(),
            b"z".to_vec(),
            b"cleanup".to_vec(),
        )
    }

    fn assert_owner_keyed_fact_rows(store: &Db, owner: FactId, expected: i64) {
        assert_eq!(
            owner_row_count(store, CONTEXT_NEEDS, owner),
            expected,
            "logical context rows"
        );
        for table in [
            TIME_WAKES,
            PENDING_TIME_RANGES,
            PENDING_PROJECTION_MATCHES,
            PENDING_PROJECTION,
        ] {
            assert_eq!(
                owner_row_count(store, table, owner),
                expected,
                "owner rows in {}",
                table.as_str()
            );
        }
    }

    fn owner_row_count(store: &Db, table: TableName, owner: FactId) -> i64 {
        let table = quoted_table_name(table).expect("quote table");
        store
            .conn()
            .query_row(
                &format!("SELECT COUNT(*) FROM {table} WHERE owner = ?1"),
                params![owner.as_slice()],
                |row| row.get(0),
            )
            .expect("count owner rows")
    }

    fn pending_match_offer_count(store: &Db, offer_owner: FactId) -> i64 {
        let offer_id = cleanup_offer(offer_owner).id();
        store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pending_projection_matches WHERE offer_id = ?1",
                params![offer_id.as_slice()],
                |row| row.get(0),
            )
            .expect("count offer rows")
    }
}
