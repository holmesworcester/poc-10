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
//! - `incoming_facts` is temp, process-local intake. Incoming rows project once;
//!   projection either moves them into durable `facts` plus
//!   `local_fact_admissions`, or drops them.
//! - `pending_projection` is the work queue keyed by fact id (`owner`) plus the
//!   time the owner entered the queue.
//! - `pending_projection_matches` and `pending_time_ranges` are pending input
//!   tables: they carry context matches and time ranges that woke an owner.
//!   They are consumed with the owner row.
//! - `context_edges` stores standing needs/offers, and `time_wakes` stores
//!   standing future wake requests emitted by durable projection.
//!
//! SQL atomicity is the safety mechanism. Submitting a fact inserts bytes,
//! admission metadata, the pending row, and any already matched context in one
//! transaction. Projecting a queued fact then consumes that pending work,
//! replaces owned needs/time wakes, appends offers, compares the output with
//! current standing context, records newly woken owners, applies row mutations,
//! records intents, and moves/drops incoming rows in one transaction. If SQLite
//! rolls back, the old queue state remains. If it commits, the projector output
//! is visible as a complete unit.
//!
//! Projectors do not query the database for missing context during a run. Matched
//! payload facts arrive through `ProjectionContext` because the pending row
//! already carries the context that woke it. Newly emitted needs may match
//! stored offers during commit, but those matches queue a later projection item.
//!
//! Queue recursion is explicit outside this item. If projection emits child
//! facts, shared effect commit stores them in `pending_projection`; if a later
//! item creates a matching offer, context fanout requeues the dependent owner.
//! Runtime later drains that work like any other queued fact.

use self::commit_effects::{
    commit_runtime_effects_in_tx, sqlite_string_error, validate_runtime_effects_for_admission,
};
#[cfg(test)]
use self::context_db::{
    insert_context_need_in_tx, insert_context_offer_in_tx, stored_context_for_owner,
};
use self::context_db::{
    pending_projection_input_context_for_owner, replace_context_for_owner_in_tx,
    wake_context_matches_in_tx,
};
use crate::core::command::AuthoredFacts;
use crate::core::context::ContextSet;
use crate::core::db::{quoted_identifier, quoted_table_name, Db, TableName};
use crate::core::effects::RuntimeEffects;
use crate::core::facts::{
    fact_from_storage_row as validate_fact_query_result, fact_id, Fact, FactId,
};
use crate::core::perf_profile as perf;
use crate::core::schema::{
    CONTEXT_EDGES, FACTS, INCOMING_FACTS, LOCAL_FACT_ADMISSIONS, PENDING_PROJECTION,
    PENDING_PROJECTION_MATCHES, PENDING_TIME_RANGES, TIME_WAKES,
};
use crate::core::wire::Writer;
use rusqlite::{params, OptionalExtension};

pub use crate::core::facts::verify_fact_id;
pub(crate) use commit_effects::commit_runtime_effects_to_db;

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
    pending_inputs: ProjectionContext,
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
    mode: ProjectionMode,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
) -> Result<bool, String> {
    let load = match load_one_projection_input(store, source, mode)? {
        None => return Ok(false),
        Some(load) => load,
    };

    let outcome = match load {
        ProjectionLoad::Loaded(input) => {
            evaluate_loaded_projection_input(projector, input, allowed_tables, fact_admission)?
        }
        ProjectionLoad::Stale { source, fact_id } => {
            // The selected queue/intake owner no longer has backing bytes, so
            // there is no fact to evaluate. Commit still owns retiring that
            // stale owner from SQL.
            ProjectionOutcome::RetireStaleInput { source, fact_id }
        }
    };

    commit_projection_outcome(store, &outcome, allowed_tables, fact_admission)?;
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
    mode: ProjectionMode,
) -> Result<Option<ProjectionLoad>, String> {
    let Some(fact_id) =
        perf::measure_result("projection_queue_load", || source.next_pending_owner(store))?
    else {
        return Ok(None);
    };

    let Some(input) = perf::measure_result("projection_load_pending_fact", || {
        load_pending_fact(store, source, fact_id, mode)
    })?
    else {
        return Ok(Some(ProjectionLoad::Stale { source, fact_id }));
    };

    Ok(Some(ProjectionLoad::Loaded(input)))
}

/// Stage 2: run the protocol projector and validate its uncommitted output.
///
/// This stage is pure with respect to SQL. It never clears a queue row, deletes
/// incoming intake, publishes context, or commits runtime effects. It only turns
/// a loaded in-memory input into an accepted or rejected outcome.
fn evaluate_loaded_projection_input(
    projector: &(impl Projector + ?Sized),
    input: ProjectionInput,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
) -> Result<ProjectionOutcome, String> {
    let source = input.source;
    let fact_id = input.fact.id;
    let projection = match perf::measure_result("projection_prepare_effects", || {
        prepare_projection(projector, input, allowed_tables, fact_admission)
    }) {
        Ok(projection) => projection,
        Err(_rejection) => {
            return Ok(ProjectionOutcome::RetireRejectedInput { source, fact_id });
        }
    };
    Ok(ProjectionOutcome::Accepted(projection))
}

/// Stage 3: commit one projection outcome as a single durable boundary.
///
/// Commit owns every SQL mutation after selection. Stale inputs are cleaned,
/// rejected inputs are retired, and accepted projector output becomes visible:
/// source queue/intake rows are consumed, standing projection state is replaced,
/// newly visible context wakes dependent facts, and runtime effects are admitted
/// last.
///
/// This is the `commit_projection_effects` boundary from the old pipeline shape,
/// kept as a named stage so the central procedure stays load -> evaluate -> commit.
fn commit_projection_outcome(
    store: &Db,
    outcome: &ProjectionOutcome,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
) -> Result<(), String> {
    perf::measure_result("projection_commit_effects", || {
        store
            .write_transaction(|tx| {
                perf::measure_result("projection_commit_tx_body", || {
                    commit_projection_outcome_in_tx(tx, outcome, allowed_tables, fact_admission)
                })
            })
            .map_err(|err| format!("commit projection effects: {err}"))
    })
}

// =============================================================================
// Load Stage Helpers
// =============================================================================

impl ProjectionSource {
    fn next_pending_owner(self, store: &Db) -> Result<Option<FactId>, String> {
        match self {
            ProjectionSource::Durable => next_durable_projection_item(store),
            ProjectionSource::Incoming => next_incoming_projection_item(store),
        }
    }

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
                Ok(
                    perf::measure_result("projection_load_pending_context_inputs", || {
                        pending_projection_input_context_for_owner(store, &fact_id)
                    })?
                    .with_time_ranges(time_ranges)
                    .with_mode(mode),
                )
            }
            ProjectionSource::Incoming => Ok(ProjectionContext::default().with_mode(mode)),
        }
    }
}

/// Read the oldest durable pending fact id without mutating the queue.
///
/// The item commit removes the row only after projection succeeds. Missing
/// facts are handled by the queue driver as stale pending rows.
fn next_durable_projection_item(store: &Db) -> Result<Option<FactId>, String> {
    store
        .conn()
        .query_row(
            r#"
            SELECT owner
            FROM pending_projection
            ORDER BY queued_at, owner
            LIMIT 1
            "#,
            [],
            |row| fact_id_column(row.get::<_, Vec<u8>>(0)?, "owner"),
        )
        .optional()
        .map_err(|err| format!("load pending projection: {err}"))
}

/// Read the next incoming fact that is not parked on missing context.
///
/// Incoming rows do not have separate pending queue rows. A standing need parks
/// the incoming owner until context fanout records a pending match for it.
fn next_incoming_projection_item(store: &Db) -> Result<Option<FactId>, String> {
    store
        .conn()
        .query_row(
            r#"
            SELECT e.id
            FROM incoming_facts e
            WHERE NOT EXISTS (
                    SELECT 1
                    FROM context_edges n
                    WHERE n.owner = e.id
                      AND n.direction = 'need'
                )
               OR EXISTS (
                    SELECT 1
                    FROM pending_projection_matches m
                    WHERE m.owner = e.id
                )
            ORDER BY e.received_at, e.id
            LIMIT 1
            "#,
            [],
            |row| fact_id_column(row.get::<_, Vec<u8>>(0)?, "incoming id"),
        )
        .optional()
        .map_err(|err| format!("load incoming facts: {err}"))
}

/// Load everything projection needs for one fact.
///
/// `pending_inputs` is the matched context and due time ranges exposed to the
/// projector for this run.
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
    let pending_inputs = source.load_pending_inputs(store, fact_id, mode)?;
    Ok(Some(ProjectionInput {
        source,
        fact,
        pending_inputs,
    }))
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
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
) -> Result<PreparedProjection, String> {
    let ProjectionInput {
        source,
        fact,
        pending_inputs,
    } = input;
    let output = perf::measure_result("projection_projector_cpu", || {
        projector.project(&fact, &pending_inputs)
    })?;
    enforce_owner_is_self(&fact, &output)?;
    let projected_context = output.context_set();
    let runtime_effects = output.effects;
    perf::measure_result("projection_validate_effects", || {
        validate_runtime_effects_for_admission(&runtime_effects, allowed_tables, fact_admission)
    })?;
    Ok(PreparedProjection {
        source,
        fact,
        retain_self: output.retain_self,
        projected_context,
        time_wakes: output.time_wakes,
        runtime_effects,
    })
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

/// Commit one projection outcome.
///
/// This function is the only stage that mutates SQL after selection. A stale
/// input retires owner-scoped broken work. A rejected input retires the selected
/// work without publishing projector state. An accepted projection commits the
/// projector's complete output.
fn commit_projection_outcome_in_tx(
    tx: &Db,
    outcome: &ProjectionOutcome,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
) -> rusqlite::Result<()> {
    match outcome {
        ProjectionOutcome::RetireStaleInput { source, fact_id } => {
            commit_stale_projection_input_in_tx(tx, *source, *fact_id)
        }
        ProjectionOutcome::RetireRejectedInput { source, fact_id } => {
            commit_rejected_projection_input_in_tx(tx, *source, *fact_id)
        }
        ProjectionOutcome::Accepted(projection) => {
            commit_projected_fact_in_tx(tx, projection, allowed_tables, fact_admission)
        }
    }
}

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

/// Commit one accepted fact's complete projection result.
///
/// This is the projection boundary, the same way `commit_handler_output` is the
/// dispatch boundary. The transaction consumes this fact's pending row and makes
/// the projector's output visible: replacement needs, append-only offers,
/// replacement time wakes, newly woken dependent facts, protocol row mutations,
/// and follow-up intents. If anything fails inside this transaction, SQLite
/// rolls the whole boundary back.
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
/// Incoming rows are volatile one-shot intake. They may emit needs as transient
/// probes, but they cannot leave standing offers or time wakes behind unless
/// projection explicitly retains them as normal facts.
fn commit_projected_fact_in_tx(
    tx: &Db,
    projection: &PreparedProjection,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
) -> rusqlite::Result<()> {
    let fact_id = projection.fact.id;
    let keep_projection_state = projection_keeps_standing_state(projection);

    // First consume the source marker. Durable inputs clear pending work.
    // Volatile incoming inputs either move into retained fact storage or
    // disappear. No projected state is published before this boundary is settled.
    commit_projection_source_boundary_in_tx(tx, projection, fact_id, keep_projection_state)?;

    if keep_projection_state {
        // Then publish standing projection state. Context replacement computes
        // additions against the transaction's current `context_edges`; only those
        // additions can wake dependent owners.
        commit_standing_projection_state_in_tx(tx, projection, fact_id)?;
    }

    // Finally commit ordinary runtime effects. Facts, row mutations, and intents
    // become visible only after the queue/intake row and projection-owned state
    // have committed successfully.
    perf::measure_result("projection_commit_runtime_effects", || {
        commit_runtime_effects_in_tx(
            tx,
            &projection.runtime_effects,
            allowed_tables,
            fact_admission,
        )
    })?;
    Ok(())
}

fn projection_keeps_standing_state(projection: &PreparedProjection) -> bool {
    let fact_id = projection.fact.id;
    let purges_self = projection.runtime_effects.purged_facts.contains(&fact_id);
    match projection.source {
        ProjectionSource::Durable => !purges_self,
        ProjectionSource::Incoming => projection.retain_self && !purges_self,
    }
}

/// Consume the input source row without publishing projection-owned state yet.
///
/// Durable inputs clear pending work. Incoming inputs are volatile: projection
/// either retains them as ordinary facts or drops them. Dropping validates that
/// no durable context/time state escapes from the volatile row.
fn commit_projection_source_boundary_in_tx(
    tx: &Db,
    projection: &PreparedProjection,
    fact_id: FactId,
    keep_projection_state: bool,
) -> rusqlite::Result<()> {
    match projection.source {
        ProjectionSource::Durable => perf::measure_result("projection_clear_pending_work", || {
            clear_pending_projection_work_in_tx(tx, fact_id)
        }),
        ProjectionSource::Incoming if keep_projection_state => {
            // Retention is the only path from volatile intake to durable fact
            // storage. `move_incoming_to_retained_in_tx` also clears transient
            // owner rows before the retained projection state is written below.
            move_incoming_to_retained_in_tx(tx, &projection.fact).map(|_| ())
        }
        ProjectionSource::Incoming => {
            // A dropped incoming row is allowed to produce effects only when it
            // has no unresolved transient needs and leaves no durable projection
            // state behind.
            validate_dropped_incoming_projection(projection).map_err(sqlite_string_error)?;
            perf::measure_result("projection_delete_incoming_fact", || {
                delete_incoming_fact_in_tx(tx, fact_id).map(|_| ())
            })
        }
    }
}

/// Publish owner-scoped projection state and wake dependents from additions.
///
/// Context comes first because wake fanout needs the current `context_edges`
/// view. Time wakes are also replacement state, but they do not influence
/// context fanout.
fn commit_standing_projection_state_in_tx(
    tx: &Db,
    projection: &PreparedProjection,
    fact_id: FactId,
) -> rusqlite::Result<()> {
    let context_additions = perf::measure_result("projection_replace_context", || {
        replace_context_for_owner_in_tx(tx, fact_id, &projection.projected_context)
    })?;
    perf::measure_result("projection_replace_time_wakes", || {
        replace_stored_time_wake_owner_rows(tx, fact_id, &projection.time_wakes)
    })?;
    perf::measure_result("projection_wake_context_matches", || {
        wake_context_matches_in_tx(tx, &context_additions).map_err(sqlite_string_error)
    })?;
    Ok(())
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
    //! They return `RuntimeEffects`: facts to admit, facts to purge, row
    //! mutations, durable intents, and ephemeral intents. A commit is the
    //! moment those pending effects are validated, written to SQLite, and made
    //! visible together.
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
    //! Committing effects changes the runtime in four ways. Purged facts remove the
    //! fact and its core-owned derived rows. New facts enter `facts`,
    //! `local_fact_admissions`, and `pending_projection`. Row mutations update
    //! protocol or core IO tables the runtime explicitly allowed. Follow-up intents
    //! are recorded after the data they depend on, so later handler passes never see
    //! queued work for state that failed to commit.
    //!
    //! The mechanism is deliberately split in two. `validate_runtime_effects`
    //! checks failures that do not need SQL: conflicting duplicate intents inside a
    //! batch and row mutations aimed at tables outside the runtime allowlist. The
    //! commit functions then rely on the database for the state-dependent checks:
    //! content-addressed facts must match their ids, typed-table inserts must
    //! be new rows or exact duplicates of the full supplied row, and intent
    //! queue inserts must keep `(kind, key)` stable.
    //!
    //! That row-table rule is not the rule for all projection state. Context rows
    //! and time wakes are handled by owner in the projection commit boundary before
    //! this helper commits shared effects: needs/time wakes are replaced, while
    //! durable offers append idempotently.
    //! Typed-table projections can change visible state by emitting explicit
    //! `DeleteWhere` and `InsertValues` mutations in the desired order.
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

    use crate::core::db::{Db, TableName};
    use crate::core::effects::RuntimeEffects;
    use crate::core::intents::{Intent, RowMutation};
    use crate::core::schema::{INTENTS, LOCAL_INTENTS};
    use std::collections::BTreeMap;

    use super::route::FactAdmissionFn;
    use super::{
        insert_facts_and_record_matches_in_tx, insert_incoming_fact_in_tx, purge_fact_in_tx,
    };

    /// Counts of newly inserted follow-up work after an effect commit.
    ///
    /// These counts are not a full change report. Purges, row mutations, and
    /// idempotent duplicates are intentionally omitted because callers use this as
    /// a scheduling signal for new facts and intents, not as an audit log.
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
    ) -> Result<(), String> {
        validate_intents(&effects.intents)?;
        validate_intents(&effects.local_intents)?;
        validate_row_mutations(&effects.row_mutations, allowed_tables)?;
        Ok(())
    }

    pub(crate) fn validate_runtime_effects_for_admission(
        effects: &RuntimeEffects,
        allowed_tables: &[TableName],
        fact_admission: Option<FactAdmissionFn>,
    ) -> Result<(), String> {
        validate_runtime_effects(effects, allowed_tables)?;
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
            .chain(effects.incoming_facts.iter())
            .try_for_each(fact_admission)
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
                        "runtime effects emitted conflicting intents for {}",
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
        fact_admission: Option<FactAdmissionFn>,
        label: &str,
    ) -> Result<RuntimeEffectCounts, String> {
        validate_runtime_effects_for_admission(effects, allowed_tables, fact_admission)?;
        store
            .write_transaction(|tx| {
                commit_runtime_effects_in_tx(tx, effects, allowed_tables, fact_admission)
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
    pub(crate) fn commit_runtime_effects_in_tx(
        tx: &Db,
        effects: &RuntimeEffects,
        allowed_tables: &[TableName],
        fact_admission: Option<FactAdmissionFn>,
    ) -> rusqlite::Result<RuntimeEffectCounts> {
        validate_fact_admissions(effects, fact_admission).map_err(sqlite_string_error)?;
        for purged in &effects.purged_facts {
            purge_fact_in_tx(tx, *purged)?;
        }

        let facts = insert_facts_and_record_matches_in_tx(tx, &effects.facts)?;

        for fact in &effects.incoming_facts {
            insert_incoming_fact_in_tx(tx, fact)?;
        }

        validate_row_mutations(&effects.row_mutations, allowed_tables)
            .map_err(sqlite_string_error)?;
        tx.apply_row_mutations_in_tx(&effects.row_mutations)?;

        let intents = insert_intents_in_tx(tx, INTENTS, &effects.intents)?;
        let local_intents = insert_intents_in_tx(tx, LOCAL_INTENTS, &effects.local_intents)?;

        Ok(RuntimeEffectCounts {
            facts,
            intents,
            local_intents,
        })
    }

    fn insert_intents_in_tx(
        tx: &Db,
        table: TableName,
        intents: &[Intent],
    ) -> rusqlite::Result<usize> {
        let mut inserted = 0usize;
        for intent in intents {
            if crate::core::handle_intent::insert_intent_work_row_in_tx(
                tx,
                table,
                &intent.work_row(),
            )? {
                inserted += 1;
            }
        }
        Ok(inserted)
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
                offers,
                ..Self::default()
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
pub(crate) mod context_db {
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
    //! `ContextSet`s. Protocol projectors produce those sets. The projection
    //! step calls this file to assemble matched `ProjectionContext`, replace stored
    //! needs, append stored offers, compare output with current standing context,
    //! and fan out wakeups to facts that may now make progress.
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
        context_set_additions, scope_key, ContextKey, ContextNeed, ContextOffer, ContextSet,
        ContextSetAdditions, Role,
    };
    use crate::core::db::Db;
    use crate::core::facts::{Fact, FactId, FactScope, ScopeKind};
    use crate::core::wire::{Reader, WireError};
    use rusqlite::params;
    use std::collections::{BTreeMap, BTreeSet};

    use super::{insert_pending_owner_in_tx, retained_fact, MatchedContext, ProjectionContext};

    const CONTEXT_NEED_DIRECTION: &str = "need";
    const CONTEXT_OFFER_DIRECTION: &str = "offer";

    /// Load a fact's standing context: the needs and offers it currently owns.
    pub(crate) fn stored_context_for_owner(
        store: &Db,
        owner: &FactId,
    ) -> Result<ContextSet, String> {
        Ok(ContextSet {
            needs: stored_needs_for_owner(store, owner)?,
            offers: stored_offers_for_owner(store, owner)?,
        }
        .normalized())
    }

    /// Replace this fact's standing needs, append its offers, and report additions.
    ///
    /// Needs are current subscriptions, so each successful durable projection
    /// replaces the owner's need rows. Offers are durable evidence emitted by an
    /// immutable fact, so they are inserted idempotently and remain until the fact
    /// is purged. The additions are computed against current stored context inside
    /// the commit transaction rather than against queue-time projection state.
    pub(crate) fn replace_context_for_owner_in_tx(
        store: &Db,
        owner: FactId,
        context: &ContextSet,
    ) -> rusqlite::Result<ContextSetAdditions> {
        let previous = stored_context_for_owner(store, &owner)
            .map_err(rusqlite::Error::InvalidParameterName)?;
        let additions = context_set_additions(&previous, context);

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
        Ok(additions)
    }

    pub(crate) fn insert_context_need_in_tx(
        store: &Db,
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
        store: &Db,
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
        store: &Db,
        offer: &ContextOffer,
    ) -> Result<(), String> {
        store
            .write_transaction(|tx| insert_context_offer_in_tx(tx, offer).map(|_| ()))
            .map_err(|err| format!("insert context offer: {err}"))
    }

    /// Load context offers whose range overlaps a single need range.
    pub(super) fn stored_overlapping_offers_for_need(
        store: &Db,
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
    fn stored_needs_for_owner(store: &Db, owner: &FactId) -> Result<Vec<ContextNeed>, String> {
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
    fn stored_offers_for_owner(store: &Db, owner: &FactId) -> Result<Vec<ContextOffer>, String> {
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
        store: &Db,
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
        store: &Db,
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
        store: &Db,
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

    /// Load context matches already attached as pending projection input.
    ///
    /// Context fanout records these rows when it queues the owner. Loading a
    /// pending item therefore does not have to search standing context for the
    /// owner's old needs before the first projector run.
    pub(crate) fn pending_projection_input_context_for_owner(
        store: &Db,
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
        store: &Db,
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
            let payload = retained_fact(store, &offer.owner)?
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

    /// Queue and record matches for owners woken by newly added context rows.
    ///
    /// Removals do not wake projection. A projector that stops needing context has
    /// already run; dependent facts wake only when a new need can now be satisfied
    /// or a new offer may satisfy existing needs. An owner is woken only when at
    /// least one overlapping edge exists; for each such owner this queues it pending
    /// and records every match its standing needs currently have. Recording from
    /// stored needs is idempotent, so distinct overlaps for the same owner collapse
    /// to one queue-and-record pass.
    pub(crate) fn wake_context_matches_in_tx(
        store: &Db,
        additions: &ContextSetAdditions,
    ) -> Result<usize, String> {
        let mut owners = BTreeSet::new();
        for need in &additions.needs {
            if !stored_overlapping_offers_for_need(store, need)?.is_empty() {
                owners.insert(need.owner);
            }
        }
        for offer in &additions.offers {
            for need in stored_overlapping_needs_for_offer(store, offer)? {
                owners.insert(need.owner);
            }
        }

        let mut changed = 0usize;
        for owner in owners {
            let queued = insert_pending_owner_in_tx(store, owner)
                .map_err(|err| format!("queue pending projection input: {err}"))?;
            let recorded = record_pending_context_inputs_for_stored_needs_in_tx(store, owner)?;
            changed += usize::from(queued > 0 || recorded > 0);
        }
        Ok(changed)
    }

    fn stored_overlapping_needs_for_offer(
        store: &Db,
        offer: &ContextOffer,
    ) -> Result<Vec<ContextNeed>, String> {
        let scope_key = scope_key(&offer.scope);
        select_context_needs(
            store,
            r#"
        SELECT owner, role, scope_key, start_key, end_key
        FROM context_edges
        WHERE direction = 'need'
          AND role = :role
          AND scope_key = :scope_key
          AND start_key <= :offer_end
          AND end_key >= :offer_start
        ORDER BY owner, start_key, end_key
        "#,
            &[
                (":role", text(offer.role.as_str())),
                (":scope_key", bytes(&scope_key)),
                (":offer_start", bytes(offer.start_key.as_bytes())),
                (":offer_end", bytes(offer.end_key.as_bytes())),
            ],
        )
    }

    /// Record pending context inputs for every standing need an owner currently holds.
    ///
    /// Used both by context wake fanout and by direct queueing paths (due time
    /// wakes, duplicate fact admission) that attach context to an owner's existing
    /// needs. Idempotent: every input row is an `INSERT OR IGNORE`.
    pub(super) fn record_pending_context_inputs_for_stored_needs_in_tx(
        store: &Db,
        owner: FactId,
    ) -> Result<usize, String> {
        let mut changed = 0usize;
        for need in stored_needs_for_owner(store, &owner)? {
            for offer in stored_overlapping_offers_for_need(store, &need)? {
                changed += record_pending_context_input_in_tx(store, &need, &offer)?;
            }
        }
        Ok(changed)
    }

    fn record_pending_context_input_in_tx(
        store: &Db,
        need: &ContextNeed,
        offer: &ContextOffer,
    ) -> Result<usize, String> {
        if need.role != offer.role || need.scope != offer.scope {
            return Err("pending projection context input role/scope mismatch".to_string());
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
    //! Projection effects and time-wake output for fact projectors.

    use crate::core::context::{ContextKey, ContextNeed, ContextOffer, ContextSet, Role};
    use crate::core::effects::RuntimeEffects;
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
        fact_purged_range_need(owner, scope, key.clone(), key)
    }

    pub fn fact_purged_offer(
        owner: FactId,
        scope: crate::core::facts::FactScope,
        key: ContextKey,
    ) -> ContextOffer {
        fact_purged_range_offer(owner, scope, key.clone(), key)
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

        pub fn fact(mut self, fact: Fact) -> Self {
            self.effects.facts.push(fact);
            self
        }

        pub fn incoming_fact(mut self, fact: Fact) -> Self {
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
    EffectiveTagFn, EnvelopeRoute, FactAdmissionFn, FactProjectorInfo, FactRoute, Projector,
    ProjectorFn, RouterProjector,
};

const OWNER_KEYED_FACT_CLEANUP_TABLES: &[TableName] = &[
    CONTEXT_EDGES,
    TIME_WAKES,
    PENDING_TIME_RANGES,
    PENDING_PROJECTION_MATCHES,
    PENDING_PROJECTION,
];

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

/// Insert a fact and mark it pending in the caller's transaction.
pub(crate) fn insert_fact_and_pending_in_tx(store: &Db, fact: &Fact) -> rusqlite::Result<bool> {
    let inserted = insert_retained_fact_in_tx(store, fact)?;
    if inserted {
        insert_pending_owner_in_tx(store, fact.id)?;
    }
    Ok(inserted)
}

fn insert_facts_and_record_matches_in_tx(store: &Db, facts: &[Fact]) -> rusqlite::Result<usize> {
    let mut inserted = 0;
    for fact in facts {
        if insert_fact_and_pending_in_tx(store, fact)? {
            context_db::record_pending_context_inputs_for_stored_needs_in_tx(store, fact.id)
                .map_err(commit_effects::sqlite_string_error)?;
            inserted += 1;
        }
    }
    Ok(inserted)
}

fn insert_pending_owner_in_tx(store: &Db, owner: FactId) -> rusqlite::Result<usize> {
    store.conn().execute(
        "INSERT OR IGNORE INTO pending_projection (owner, queued_at) VALUES (?1, ?2)",
        params![owner.as_slice(), queue_now_ms()?],
    )
}

fn insert_incoming_fact_in_tx(store: &Db, fact: &Fact) -> rusqlite::Result<bool> {
    if let Some(bytes) = fact_bytes_by_id_in_tx(store, &fact.id)? {
        if bytes == fact.bytes {
            return Ok(false);
        }
        return Err(projection_sql_error(
            "conflicting retained row for incoming fact",
        ));
    }

    let (scope, scope_kind, scope_id) = fact.scope.storage_columns();
    let changed = store.conn().execute(
        "INSERT OR IGNORE INTO incoming_facts
            (id, scope, scope_kind, scope_id, received_at, bytes)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            fact.id.as_slice(),
            scope,
            scope_kind,
            scope_id.as_slice(),
            sqlite_u64(fact.timestamp, "incoming fact received_at")?,
            fact.bytes.as_slice()
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
    changed |= delete_owner_rows_from_tables(store, OWNER_KEYED_FACT_CLEANUP_TABLES, owner)? > 0;
    changed |= delete_rows_by_blob_column_in_tx(
        store,
        PENDING_PROJECTION_MATCHES,
        "offer_owner",
        owner.as_slice(),
    )? > 0;
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
    commit_runtime_effects_to_db(store, &effects, allowed_tables, fact_admission, label)?;
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

#[cfg(test)]
mod contract_tests {
    use super::*;
    use crate::core::context::{ContextKey, ContextNeed, ContextOffer, ContextSetAdditions, Role};
    use crate::core::facts::{FactId, FactScope};
    use crate::core::intents::{Intent, IntentKind};
    use rusqlite::OptionalExtension;
    use std::cell::Cell;

    fn submit_fact_to_db(store: &Db, fact: Fact) -> Result<bool, String> {
        submit_facts_to_db(store, [fact]).map(|inserted| inserted > 0)
    }

    fn run_projection(
        projector: &(impl Projector + ?Sized),
        fact: &Fact,
        pending_inputs: ProjectionContext,
    ) -> Result<PreparedProjection, String> {
        prepare_projection(
            projector,
            ProjectionInput {
                source: ProjectionSource::Durable,
                fact: fact.clone(),
                pending_inputs,
            },
            &[],
            None,
        )
    }

    fn expect_loaded(load: Option<ProjectionLoad>) -> ProjectionInput {
        match load.expect("queued input") {
            ProjectionLoad::Loaded(input) => input,
            ProjectionLoad::Stale { .. } => panic!("expected loaded projection input"),
        }
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
                start_key: ContextKey::from_bytes(fact.id),
                end_key: ContextKey::from_bytes(fact.id),
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
    fn projection_evaluation_does_not_clear_rejected_durable_pending_work() {
        let store = Db::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
            .expect("open db");
        let fact = Fact::new(FactScope::Global, 1, b"durable reject".to_vec());
        submit_fact_to_db(&store, fact.clone()).expect("submit pending fact");
        let projector = test_projector(|_fact: &Fact, _context: &ProjectionContext| {
            Err("projector rejected durable fact".to_string())
        });

        let input = expect_loaded(
            load_one_projection_input(&store, ProjectionSource::Durable, ProjectionMode::Normal)
                .expect("load projection input"),
        );
        let outcome = evaluate_loaded_projection_input(&projector, input, &[], None)
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

        commit_projection_outcome(&store, &outcome, &[], None).expect("commit rejection");

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
            load_one_projection_input(&store, ProjectionSource::Incoming, ProjectionMode::Normal)
                .expect("load projection input"),
        );
        let outcome = evaluate_loaded_projection_input(&projector, input, &[], None)
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

        commit_projection_outcome(&store, &outcome, &[], None).expect("commit rejection");

        assert!(incoming_fact_by_id(&store, &fact.id)
            .expect("load incoming fact")
            .is_none());
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
        };

        let next = run_projection(&projector, &fact, ProjectionContext::new(vec![offer]))
            .expect("projection with context");

        assert!(next.projected_context.needs.is_empty());
        assert_eq!(next.runtime_effects.intents.len(), 1);
        assert_eq!(next.runtime_effects.intents[0].kind.as_str(), "followup");
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
    fn projection_drain_resolves_new_range_need_that_matches_existing_offer() {
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

        assert!(progress);
        assert_eq!(
            intent_payload_for(&store, "queued_context_ready", &target.id),
            offered.id.to_vec()
        );
        assert_eq!(pending_projection_match_count(&store, target.id), 0);
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
    fn projection_drain_can_keep_watch_need_after_it_matches() {
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
        };
        crate::core::project_fact::context_db::insert_context_offer_for_test(&store, &offer)
            .expect("insert stored offer");

        let projector = watch_need(role, key, "observed");
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
                ProjectionMode::Normal,
                allowed_tables,
                fact_admission,
            )?;
            if !step {
                step = crate::core::project_fact::project_one(
                    store,
                    projector,
                    ProjectionSource::Incoming,
                    ProjectionMode::Normal,
                    allowed_tables,
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
                "SELECT payload FROM intents WHERE kind = ?1 AND idempotence_key = ?2",
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
// loading, projector execution, incoming retention, context wake fanout,
// time-wake replacement, and projection effect commit.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{ContextKey, ContextNeed, ContextOffer, Role};
    use crate::core::facts::{Fact, FactId, FactScope};
    use crate::core::schema::CORE_SCHEMA_SOURCE;

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
    fn next_incoming_projection_item_treats_pending_matches_as_ready() {
        let db = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE]).expect("open db");
        let ready = Fact::new(FactScope::Local, 1, b"ready incoming".to_vec());
        let blocked = Fact::new(FactScope::Local, 0, b"blocked incoming".to_vec());

        db.write_transaction(|tx| {
            insert_incoming_fact_in_tx(tx, &ready)?;
            insert_incoming_fact_in_tx(tx, &blocked)?;
            tx.conn().execute(
                "INSERT INTO context_edges
                    (owner, direction, role, scope_key, start_key, end_key)
                 VALUES (?1, 'need', 'incoming_context', ?2, ?3, ?4)",
                params![
                    blocked.id.as_slice(),
                    b"scope".as_slice(),
                    b"a".as_slice(),
                    b"z".as_slice()
                ],
            )?;
            Ok(())
        })
        .expect("seed incoming facts");

        assert_eq!(
            next_incoming_projection_item(&db).expect("next incoming"),
            Some(ready.id)
        );

        db.conn()
            .execute(
                "INSERT INTO pending_projection_matches
                    (owner, need_role, need_scope_key, need_start_key, need_end_key,
                     offer_owner, offer_start_key, offer_end_key)
                 VALUES (?1, 'incoming_context', ?2, ?3, ?4, ?5, ?3, ?4)",
                params![
                    blocked.id.as_slice(),
                    b"scope".as_slice(),
                    b"a".as_slice(),
                    b"z".as_slice(),
                    ready.id.as_slice()
                ],
            )
            .expect("record pending match");

        assert_eq!(
            next_incoming_projection_item(&db).expect("matched incoming"),
            Some(blocked.id)
        );
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
                start_key: need.start_key.clone(),
                end_key: need.end_key.clone(),
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
        store.conn().execute(
            "INSERT INTO context_edges
                (owner, direction, role, scope_key, start_key, end_key)
             VALUES (?1, 'need', 'cleanup_role', ?2, ?3, ?4)",
            params![
                owner.as_slice(),
                b"scope".as_slice(),
                b"a".as_slice(),
                b"z".as_slice()
            ],
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
        store.conn().execute(
            "INSERT INTO pending_projection_matches
                (owner, need_role, need_scope_key, need_start_key, need_end_key,
                 offer_owner, offer_start_key, offer_end_key)
             VALUES (?1, 'cleanup_role', ?2, ?3, ?4, ?5, ?3, ?4)",
            params![
                owner.as_slice(),
                b"scope".as_slice(),
                b"a".as_slice(),
                b"z".as_slice(),
                offer_owner.as_slice()
            ],
        )?;
        Ok(())
    }

    fn assert_owner_keyed_fact_rows(store: &Db, owner: FactId, expected: i64) {
        for table in OWNER_KEYED_FACT_CLEANUP_TABLES {
            assert_eq!(
                owner_row_count(store, *table, owner),
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
        store
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM pending_projection_matches WHERE offer_owner = ?1",
                params![offer_owner.as_slice()],
                |row| row.get(0),
            )
            .expect("count offer rows")
    }
}
