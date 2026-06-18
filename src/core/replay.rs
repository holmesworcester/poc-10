//! Replay entry point for the generic runtime.
//!
//! Replay rebuilds all non-fact runtime state from retained facts. It is the
//! mechanism behind a safe upgrade: queued intents, projected rows, standing
//! context, time wakes, incoming inputs, and outgoing network queues
//! are not protocol truth, so a process can drop them and reproject retained
//! facts to recover read-model rows, standing context, time wakes, sync indexes,
//! and key material. The same entry point backs the
//! `replay`/`replay-check` diagnostics, which prove that replay is idempotent
//! and independent of fact projection order.
//!
//! Ownership boundary. Replay reuses the ordinary projection and dispatch
//! workers; it adds four things on top: a db-owned reset of schema-declared
//! replay tables, SQL inserts that mark retained facts pending in replay mode,
//! projection-order control used by the reverse and scrambled diagnostics, and
//! replay-mode projection/handler context. Projectors decide how their facts
//! behave in replay through `ProjectionContext::is_replay()`.
//!
//! Invariants. Replay must not perform network IO or run operational wall-clock
//! decisions. It re-materializes standing time wakes but does not decide that
//! any of them are due. Any network row means a replay-mode handler crossed
//! into transport output, and replay returns an error instead of a report.
//! Recurring operational schedules are not installed during replay, so they
//! cannot fire.
//!
//! Replay state is explicit: core and protocol schema sources declare which
//! tables are retained fact storage and which tables are resettable runtime
//! state, so replay never decides by ad hoc SQLite table enumeration.

use crate::core::db::{quoted_table_name, Db, TableName};
use crate::core::effects::StorageRequirementCheck;
use crate::core::facts::FactId;
use crate::core::handle_intent::{
    dispatch_one_intent, HandlerRoute, HandlerSet, IntentQueue, WorkStatus,
};
use crate::core::network::OUTGOING_TABLE;
use crate::core::project_fact::{self, FactAdmissionFn, ProjectionSource, Projector};
use crate::core::schema::{CONTEXT_EDGES, FACTS, INTENTS, LOCAL_INTENTS, TIME_WAKES};
use rusqlite::params;
use std::collections::BTreeSet;

const REPLAY_WORK_LIMIT: usize = 4096;
const REPLAY_MAX_DRAIN_STEPS: usize = 256;

/// Core runtime index tables that are protocol-derived but are not read-model
/// row mutations; counted separately from materialized rows.
const RUNTIME_INDEX_TABLES: &[TableName] = &[FACTS, CONTEXT_EDGES, TIME_WAKES];

/// Order in which retained facts are admitted for projection during replay.
///
/// The canonical order matches normal operation (admission order). The reverse
/// and scrambled orders exist to prove projection-order independence: parking on
/// missing context lets any order converge to the same derived state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayOrder {
    /// Admit retained facts in canonical admission order, all at once.
    Canonical,
    /// Admit retained facts newest-first, one at a time.
    Reverse,
    /// Admit retained facts in a deterministic seeded shuffle, one at a time.
    Scramble { seed: u64 },
}

/// State counts from one replay pass, surfaced by the `replay` diagnostic.
///
/// These are deterministic given the same retained facts. `network_rows` must be
/// zero; a non-zero value is reported as an error by [`run_replay`] rather than
/// returned here.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplayReport {
    /// Durable queued intents dropped before the wipe.
    pub dropped_durable_intents: usize,
    /// Local queued intents dropped before the wipe.
    pub dropped_local_intents: usize,
    /// Derived-state tables cleared by the wipe.
    pub wiped_tables: usize,
    /// Distinct retained facts marked pending for projection.
    pub retained_facts: usize,
    /// Facts created during replay (for example deterministic key wraps).
    pub emitted_facts: usize,
    /// Facts purged during replay (for example via retirement projection).
    pub purged_facts: usize,
    /// Standing time-wake rows remaining after replay drains.
    pub standing_time_wakes: usize,
    /// Standing context edges materialized by replay.
    pub context_edges: usize,
    /// Materialized read-model / sync / connection rows after replay.
    pub row_mutations: usize,
    /// Network queue rows produced during replay; must be zero.
    pub network_rows: usize,
}

/// Result of the destructive rebuild request committed by projection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RebuildReport {
    /// Derived-state tables cleared by the wipe.
    pub wiped_tables: usize,
    /// Retained facts found after the wipe.
    pub retained_facts: usize,
    /// Retained facts marked pending in replay mode.
    pub queued_facts: usize,
}

/// Run the replay entry point against an opened db.
///
/// Steps: count and drop queued intents, wipe derived state, mark retained facts
/// pending in the requested order, then run replay-mode queue steps until the
/// replay barrier is idle. Returns state counts, or an error if replay produced
/// network rows before the barrier.
pub fn run_replay(
    db: &Db,
    projector: &dyn Projector,
    routes: &'static [HandlerRoute],
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    storage_requirement_check: Option<StorageRequirementCheck>,
    order: ReplayOrder,
) -> Result<ReplayReport, String> {
    let mut report = ReplayReport {
        dropped_durable_intents: table_count(db, INTENTS)?,
        dropped_local_intents: table_count(db, LOCAL_INTENTS)?,
        ..ReplayReport::default()
    };
    let facts_before = fact_id_set(db)?;

    report.wiped_tables = clear_replay_reset_tables(db)?;
    report.retained_facts = table_count(db, FACTS)?;

    let handlers = HandlerSet::new(routes);
    match order {
        ReplayOrder::Canonical => {
            enqueue_all_retained_facts_for_replay(db)?;
            drain_replay_barrier(
                db,
                projector,
                &handlers,
                allowed_tables,
                fact_admission,
                storage_requirement_check,
            )?;
        }
        ReplayOrder::Reverse | ReplayOrder::Scramble { .. } => {
            for fact_id in ordered_fact_ids(db, order)? {
                enqueue_retained_fact_for_replay(db, fact_id)?;
                drain_replay_barrier(
                    db,
                    projector,
                    &handlers,
                    allowed_tables,
                    fact_admission,
                    storage_requirement_check,
                )?;
            }
            drain_replay_barrier(
                db,
                projector,
                &handlers,
                allowed_tables,
                fact_admission,
                storage_requirement_check,
            )?;
        }
    }

    let facts_after = fact_id_set(db)?;
    report.emitted_facts = facts_after.difference(&facts_before).count();
    report.purged_facts = facts_before.difference(&facts_after).count();
    report.standing_time_wakes = table_count(db, TIME_WAKES)?;
    report.context_edges = table_count(db, CONTEXT_EDGES)?;
    report.row_mutations = materialized_row_count(db)?;
    let remaining_queued_work = table_count(db, INTENTS)? + table_count(db, LOCAL_INTENTS)?;
    report.network_rows = table_count(db, OUTGOING_TABLE)?;

    if remaining_queued_work > 0 {
        return Err(format!(
            "replay left {remaining_queued_work} queued intent rows after the drain barrier"
        ));
    }

    if report.network_rows > 0 {
        return Err(format!(
            "replay produced {} network queue rows before the barrier; a replay-mode handler crossed into network IO",
            report.network_rows
        ));
    }

    Ok(report)
}

/// Clear every schema-declared replay-resettable table.
///
/// Replay callers do not provide a keep-list. Protected tables are excluded by
/// construction when the database opens, so retained fact storage cannot be
/// cleared by a replay bug in a caller.
pub fn clear_replay_reset_tables(db: &Db) -> Result<usize, String> {
    db.write_transaction(clear_replay_reset_tables_in_tx)
        .map_err(|err| format!("clear replay reset tables: {err}"))
}

/// Clear derived/runtime state and mark retained facts pending in replay mode.
///
/// This is the production rebuild primitive. It does not drain work; the normal
/// runtime queue loop projects the resulting rows.
pub(crate) fn rebuild_derived_state_in_tx(db: &Db) -> Result<RebuildReport, String> {
    let wiped_tables = clear_replay_reset_tables_in_tx(db)
        .map_err(|err| format!("clear replay reset tables: {err}"))?;
    let retained_facts = table_count(db, FACTS)?;
    let queued_facts = enqueue_all_retained_facts_for_replay_in_tx(db)?;
    Ok(RebuildReport {
        wiped_tables,
        retained_facts,
        queued_facts,
    })
}

fn clear_replay_reset_tables_in_tx(db: &Db) -> rusqlite::Result<usize> {
    let mut cleared = 0usize;
    for table in db.replay_reset_tables() {
        let quoted = quoted_table_name(*table)?;
        db.conn().execute(&format!("DELETE FROM {quoted}"), [])?;
        cleared += 1;
    }
    Ok(cleared)
}

/// Drain replay work in the same visible queue order as the live runtime loop.
///
/// Each barrier step does bounded durable projection, incoming projection,
/// durable intent dispatch, and local intent dispatch. Projection and dispatch
/// keep their own SQLite transactions; replay's job is only to keep taking
/// bounded queue steps until all queues are idle before live network/recurring
/// work can resume.
fn drain_replay_barrier(
    db: &Db,
    projector: &dyn Projector,
    handlers: &HandlerSet,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    storage_requirement_check: Option<StorageRequirementCheck>,
) -> Result<(), String> {
    for _ in 0..REPLAY_MAX_DRAIN_STEPS {
        let mut status = WorkStatus::idle();
        status.merge(drain_replay_projection_queue(
            db,
            projector,
            ProjectionSource::Durable,
            allowed_tables,
            fact_admission,
            storage_requirement_check,
        )?);
        status.merge(drain_replay_projection_queue(
            db,
            projector,
            ProjectionSource::Incoming,
            allowed_tables,
            fact_admission,
            storage_requirement_check,
        )?);

        status.merge(drain_replay_intent_queue(
            db,
            handlers,
            IntentQueue::Durable,
            allowed_tables,
            fact_admission,
            storage_requirement_check,
        )?);
        status.merge(drain_replay_intent_queue(
            db,
            handlers,
            IntentQueue::Local,
            allowed_tables,
            fact_admission,
            storage_requirement_check,
        )?);

        if status.is_idle() {
            return Ok(());
        }
    }
    Err("replay drain exceeded the step limit".to_string())
}

fn drain_replay_projection_queue(
    db: &Db,
    projector: &dyn Projector,
    source: ProjectionSource,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    storage_requirement_check: Option<StorageRequirementCheck>,
) -> Result<WorkStatus, String> {
    let mut status = WorkStatus::idle();
    for _ in 0..REPLAY_WORK_LIMIT {
        let step_status = project_fact::project_one(
            db,
            projector,
            source,
            allowed_tables,
            fact_admission,
            storage_requirement_check,
        )?;
        if step_status.is_idle() {
            break;
        }
        status.merge(step_status);
    }
    Ok(status)
}

fn drain_replay_intent_queue(
    db: &Db,
    handlers: &HandlerSet,
    queue: IntentQueue,
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    storage_requirement_check: Option<StorageRequirementCheck>,
) -> Result<WorkStatus, String> {
    let mut status = WorkStatus::idle();
    for _ in 0..REPLAY_WORK_LIMIT {
        let step_status = dispatch_one_intent(
            db,
            handlers,
            queue,
            allowed_tables,
            fact_admission,
            storage_requirement_check,
        )?;
        if step_status.is_idle() {
            break;
        }
        status.merge(step_status);
        if step_status.retried {
            break;
        }
    }
    Ok(status)
}

/// Mark every retained fact as replay pending in one SQL statement.
///
/// `facts` is replay-protected durable storage; `pending_projection` is
/// resettable runtime work. This insert is safe to repeat because the queue is
/// keyed by owner.
fn enqueue_all_retained_facts_for_replay(db: &Db) -> Result<usize, String> {
    enqueue_all_retained_facts_for_replay_in_tx(db)
}

fn enqueue_all_retained_facts_for_replay_in_tx(db: &Db) -> Result<usize, String> {
    db.conn()
        .execute(
            "INSERT OR IGNORE INTO pending_projection (owner, queued_at, priority, replay)
             SELECT f.id, m.received_at, 100, 1
             FROM facts f
             JOIN local_fact_admissions m ON m.fact_id = f.id",
            [],
        )
        .map_err(|err| format!("enqueue retained facts for replay: {err}"))
}

/// Mark one retained fact as replay pending for order-variation diagnostics.
fn enqueue_retained_fact_for_replay(db: &Db, fact_id: FactId) -> Result<bool, String> {
    let inserted = db
        .conn()
        .execute(
            "INSERT OR IGNORE INTO pending_projection (owner, queued_at, priority, replay)
             VALUES (?1, 0, 100, 1)",
            params![fact_id.as_slice()],
        )
        .map_err(|err| format!("enqueue retained fact for replay: {err}"))?;
    if inserted == 0 {
        db.conn()
            .execute(
                "UPDATE pending_projection
                 SET replay = 1
                 WHERE owner = ?1 AND replay = 0",
                params![fact_id.as_slice()],
            )
            .map_err(|err| format!("mark retained fact replay pending: {err}"))?;
    }
    Ok(inserted > 0)
}

/// Compute the fact admission order for the requested replay order.
fn ordered_fact_ids(db: &Db, order: ReplayOrder) -> Result<Vec<FactId>, String> {
    // Canonical admission order: received_at then fact id, matching durable
    // pending projection selection.
    let sql = "SELECT f.id
               FROM facts f
               JOIN local_fact_admissions m ON m.fact_id = f.id
               ORDER BY m.received_at, f.id";
    let mut stmt = db
        .conn()
        .prepare(sql)
        .map_err(|err| format!("load canonical fact order: {err}"))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|err| format!("load canonical fact order: {err}"))?;
    let mut canonical = Vec::new();
    for row in rows {
        let bytes = row.map_err(|err| format!("load canonical fact order: {err}"))?;
        canonical.push(fact_id_from_bytes(bytes)?);
    }

    Ok(match order {
        ReplayOrder::Canonical => canonical,
        ReplayOrder::Reverse => {
            canonical.reverse();
            canonical
        }
        ReplayOrder::Scramble { seed } => {
            // Deterministic shuffle: sort by a seeded hash of each fact id.
            canonical.sort_by_key(|id| scramble_key(seed, id));
            canonical
        }
    })
}

fn scramble_key(seed: u64, fact_id: &FactId) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo:replay-scramble:v1");
    hasher.update(&seed.to_le_bytes());
    hasher.update(fact_id);
    *hasher.finalize().as_bytes()
}

fn fact_id_set(db: &Db) -> Result<BTreeSet<FactId>, String> {
    let mut stmt = db
        .conn()
        .prepare("SELECT id FROM facts")
        .map_err(|err| format!("load fact ids: {err}"))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, Vec<u8>>(0))
        .map_err(|err| format!("load fact ids: {err}"))?;
    let mut set = BTreeSet::new();
    for row in rows {
        let bytes = row.map_err(|err| format!("load fact ids: {err}"))?;
        set.insert(fact_id_from_bytes(bytes)?);
    }
    Ok(set)
}

fn fact_id_from_bytes(bytes: Vec<u8>) -> Result<FactId, String> {
    bytes
        .try_into()
        .map_err(|_| "fact id column is not 32 bytes".to_string())
}

/// Total materialized read-model / sync / connection rows after replay.
fn materialized_row_count(db: &Db) -> Result<usize, String> {
    let mut total = 0;
    for table in db.replay_summary_tables() {
        if RUNTIME_INDEX_TABLES.contains(table) {
            continue;
        }
        total += table_count(db, *table)?;
    }
    Ok(total)
}

fn table_count(db: &Db, table: TableName) -> Result<usize, String> {
    db.table_row_count(table)
        .map_err(|err| format!("count {}: {err}", table.as_str()))
}
