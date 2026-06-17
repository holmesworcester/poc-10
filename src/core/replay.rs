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
//! workers; it adds three things on top: a db-owned reset of schema-declared
//! replay tables, projection-order control used by the reverse and scrambled
//! diagnostics, and replay-mode projection context. Projectors decide how their
//! facts behave in replay through `ProjectionContext::is_replay()`.
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
use crate::core::facts::FactId;
use crate::core::handle_intent::{dispatch_intents, HandlerRoute, HandlerSet, WorkStatus};
use crate::core::intents::HandlerMode;
use crate::core::network::OUTGOING_TABLE;
use crate::core::project_fact::{self, FactAdmissionFn, Projector, RuntimeEffectMode};
use crate::core::schema::{CONTEXT_EDGES, FACTS, INTENTS, LOCAL_INTENTS, TIME_WAKES};
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

/// Counters from one replay pass, surfaced by the `replay` diagnostic.
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
    /// Total projection runs, including context- and time-driven reprojections.
    pub projected_facts: usize,
    /// Facts created during replay (for example deterministic key wraps).
    pub emitted_facts: usize,
    /// Facts purged during replay (for example via retirement projection).
    pub purged_facts: usize,
    /// Standing time-wake rows remaining after replay drains.
    pub standing_time_wakes: usize,
    /// Intents dispatched before the replay barrier.
    pub replayed_intents: usize,
    /// Standing context edges materialized by replay.
    pub context_edges: usize,
    /// Materialized read-model / sync / connection rows after replay.
    pub row_mutations: usize,
    /// Network queue rows produced during replay; must be zero.
    pub network_rows: usize,
}

/// Run the replay entry point against an opened db.
///
/// Steps: count and drop queued intents, wipe derived state, mark retained facts
/// pending in the requested order, then run replay-mode queue steps until the
/// replay barrier is idle. Returns counters, or an error if replay produced
/// network rows before the barrier.
pub fn run_replay(
    db: &Db,
    projector: &dyn Projector,
    routes: &'static [HandlerRoute],
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    order: ReplayOrder,
) -> Result<ReplayReport, String> {
    let mut report = ReplayReport {
        dropped_durable_intents: table_count(db, INTENTS)?,
        dropped_local_intents: table_count(db, LOCAL_INTENTS)?,
        ..ReplayReport::default()
    };
    let facts_before = fact_id_set(db)?;

    report.wiped_tables = wipe_derived_state(db)?;
    report.retained_facts = table_count(db, FACTS)?;

    let drive = ReplayDrive::new(db, projector, allowed_tables, fact_admission, routes);
    let mut counters = ReplayCounters::default();
    match order {
        ReplayOrder::Canonical => {
            project_fact::enqueue_retained_facts_for_replay(db)?;
            drive.drain_until_barrier(&mut counters)?;
        }
        ReplayOrder::Reverse | ReplayOrder::Scramble { .. } => {
            for fact_id in ordered_fact_ids(db, order)? {
                project_fact::enqueue_retained_fact_for_replay(db, fact_id)?;
                drive.drain_until_barrier(&mut counters)?;
            }
            drive.drain_until_barrier(&mut counters)?;
        }
    }

    let facts_after = fact_id_set(db)?;
    report.emitted_facts = facts_after.difference(&facts_before).count();
    report.purged_facts = facts_before.difference(&facts_after).count();
    report.projected_facts = counters.projected_facts;
    report.replayed_intents = counters.replayed_intents;
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
    db.write_transaction(|tx| {
        let mut cleared = 0usize;
        for table in tx.replay_reset_tables() {
            let quoted = quoted_table_name(*table)?;
            tx.conn().execute(&format!("DELETE FROM {quoted}"), [])?;
            cleared += 1;
        }
        Ok(cleared)
    })
    .map_err(|err| format!("clear replay reset tables: {err}"))
}

#[derive(Debug, Clone, Default)]
struct ReplayCounters {
    projected_facts: usize,
    replayed_intents: usize,
}

/// Replay-mode work driver over the ordinary projection and dispatch workers.
///
/// It instantiates the ordinary handler routes and passes replay mode through
/// handler context. Each step drains one projection batch and one intent batch;
/// the barrier repeats that visible queue order until a step is idle.
struct ReplayDrive<'a> {
    db: &'a Db,
    projector: &'a dyn Projector,
    allowed_tables: &'a [TableName],
    fact_admission: Option<FactAdmissionFn>,
    handlers: HandlerSet,
}

impl<'a> ReplayDrive<'a> {
    fn new(
        db: &'a Db,
        projector: &'a dyn Projector,
        allowed_tables: &'a [TableName],
        fact_admission: Option<FactAdmissionFn>,
        routes: &'static [HandlerRoute],
    ) -> Self {
        let handlers = HandlerSet::new(routes);
        Self {
            db,
            projector,
            allowed_tables,
            fact_admission,
            handlers,
        }
    }

    fn drain_until_barrier(&self, counters: &mut ReplayCounters) -> Result<(), String> {
        for _ in 0..REPLAY_MAX_DRAIN_STEPS {
            if self.drain_one_step(counters)?.is_idle() {
                return Ok(());
            }
        }
        Err("replay drain exceeded the step limit".to_string())
    }

    fn drain_one_step(&self, counters: &mut ReplayCounters) -> Result<WorkStatus, String> {
        let mut status = WorkStatus::idle();
        status.merge(self.drain_projection(counters)?);
        status.merge(self.dispatch_replay(counters)?);
        Ok(status)
    }

    fn drain_projection(&self, counters: &mut ReplayCounters) -> Result<WorkStatus, String> {
        let progress = project_fact::drain_projection(
            self.db,
            self.projector,
            self.allowed_tables,
            self.fact_admission,
            REPLAY_WORK_LIMIT,
        )?;
        counters.projected_facts += progress.projected;
        Ok(progress.status)
    }

    fn dispatch_replay(&self, counters: &mut ReplayCounters) -> Result<WorkStatus, String> {
        let progress = dispatch_intents(
            self.db,
            &self.handlers,
            self.allowed_tables,
            self.fact_admission,
            REPLAY_WORK_LIMIT,
            HandlerMode::Replay,
            RuntimeEffectMode::Replay,
        )?;
        counters.replayed_intents += progress.dispatched;
        Ok(progress.status)
    }
}

/// Wipe every schema-declared replay-resettable table.
fn wipe_derived_state(db: &Db) -> Result<usize, String> {
    clear_replay_reset_tables(db)
}

/// Compute the fact admission order for the requested replay order.
fn ordered_fact_ids(db: &Db, order: ReplayOrder) -> Result<Vec<FactId>, String> {
    // Canonical admission order: received_at then fact id, matching the pending
    // projection batch ordering used in normal operation.
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
