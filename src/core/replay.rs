//! Replay entry point for the generic runtime.
//!
//! Replay rebuilds all non-fact runtime state from retained facts. It is the
//! mechanism behind a safe upgrade: queued intents, projected rows, standing
//! context, time wakes, incoming inputs, network queues, and local clock state
//! are not protocol truth, so a process can drop them and reproject retained
//! facts to recover read-model rows, standing context, semantic time wakes,
//! sync indexes, and key material. The same entry point backs the
//! `replay`/`replay-check` diagnostics, which prove that replay is idempotent
//! and independent of fact projection order.
//!
//! Ownership boundary. Replay reuses the ordinary projection and dispatch
//! workers; it adds three things on top: a store-owned reset of schema-declared
//! replay tables, projection-order control used by the reverse and scrambled
//! diagnostics, and replay-mode projection context. Projectors decide how their
//! facts behave in replay through `ProjectionContext::is_replay()`.
//!
//! Invariants. Replay must not perform network IO or run operational wall-clock
//! decisions. It admits wall-clock context only through the replayable semantic
//! time-wake timelines the caller supplies, and it asserts that no network queue
//! rows were produced. Any network row means a replay-mode handler crossed into
//! transport output, and replay returns an error instead of a report. Recurring
//! operational schedules are not installed during replay, so they cannot fire.
//!
//! State summary. `state_summary` hashes the store-declared replay summary
//! tables in a canonical, order-independent way. Core and protocol schema
//! sources declare which tables are retained fact storage, resettable runtime
//! state, and summary-visible derived state, so replay never decides by ad hoc
//! SQLite table enumeration.

use crate::core::daemon::DaemonTimeWake;
use crate::core::facts::FactId;
use crate::core::handle_intent::{dispatch_intents, HandlerRoute, HandlerSet};
use crate::core::intents::HandlerMode;
use crate::core::network::{INBOUND_TABLE, OUTBOUND_TABLE};
use crate::core::project_fact::{self, FactAdmissionFn, Projector, RuntimeEffectMode};
use crate::core::schema::{CONTEXT_EDGES, FACTS, INTENTS, LOCAL_INTENTS, TIME_WAKES};
use crate::core::store::{Store, TableName};
use std::collections::BTreeSet;

const REPLAY_WORK_LIMIT: usize = 4096;
const REPLAY_FIXPOINT_ROUNDS: usize = 256;

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
    /// Due time-wake rows admitted from replayable semantic timelines.
    pub semantic_time_wakes: usize,
    /// Standing time-wake rows remaining after replay settles.
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

/// One hashed state area in a [`StateSummary`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AreaSummary {
    /// Table name owning this area.
    pub area: String,
    /// Canonical hash of the area's rows.
    pub hash: [u8; 32],
    /// Row count in the area.
    pub count: usize,
}

/// A stable, order-independent digest of replay-relevant state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateSummary {
    /// Overall digest combining every per-area hash and count.
    pub state_hash: [u8; 32],
    /// Per-area hashes and counts, ordered by area name.
    pub areas: Vec<AreaSummary>,
}

/// One replay-check pass: a named replay plan and the state it reached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayCheckPass {
    /// Pass name (canonical, idempotent, reverse, scramble-N).
    pub name: String,
    /// State digest this pass reached on its scratch copy.
    pub state_hash: [u8; 32],
    /// Per-area differences from the canonical pass, if any.
    pub area_diffs: Vec<String>,
}

/// Result of comparing every replay-check pass against the canonical pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayCheckReport {
    /// State digest of the canonical pass; every pass should match it.
    pub canonical_hash: [u8; 32],
    /// All passes that ran, including the canonical pass itself.
    pub passes: Vec<ReplayCheckPass>,
    /// Names of passes whose digest diverged from canonical.
    pub mismatched: Vec<String>,
}

/// Compare each replay pass summary against the canonical pass.
///
/// `passes` is `(name, summary)` for every pass, with the canonical pass first.
/// The report records per-area diffs for any pass whose digest diverges, which
/// localizes a determinism bug to a specific table.
pub fn compare_replay_passes(passes: Vec<(String, StateSummary)>) -> ReplayCheckReport {
    let canonical = passes
        .first()
        .map(|(_, summary)| summary.clone())
        .expect("replay-check runs at least the canonical pass");
    let mut report = ReplayCheckReport {
        canonical_hash: canonical.state_hash,
        passes: Vec::new(),
        mismatched: Vec::new(),
    };
    for (name, summary) in passes {
        let area_diffs = if summary.state_hash == canonical.state_hash {
            Vec::new()
        } else {
            report.mismatched.push(name.clone());
            area_diffs(&canonical, &summary)
        };
        report.passes.push(ReplayCheckPass {
            name,
            state_hash: summary.state_hash,
            area_diffs,
        });
    }
    report
}

/// Report which state areas differ between two summaries, with their counts.
fn area_diffs(left: &StateSummary, right: &StateSummary) -> Vec<String> {
    let mut names: Vec<&str> = left
        .areas
        .iter()
        .map(|area| area.area.as_str())
        .chain(right.areas.iter().map(|area| area.area.as_str()))
        .collect();
    names.sort_unstable();
    names.dedup();

    let mut diffs = Vec::new();
    for name in names {
        let left_area = left.areas.iter().find(|area| area.area == name);
        let right_area = right.areas.iter().find(|area| area.area == name);
        let differs = match (left_area, right_area) {
            (Some(l), Some(r)) => l.hash != r.hash || l.count != r.count,
            _ => true,
        };
        if differs {
            let left_count = left_area.map(|area| area.count).unwrap_or(0);
            let right_count = right_area.map(|area| area.count).unwrap_or(0);
            diffs.push(format!("{name}: canonical={left_count} pass={right_count}"));
        }
    }
    diffs
}

/// Run the replay entry point against an opened store.
///
/// Steps: count and drop queued intents, wipe derived state, mark retained facts
/// pending in the requested order, then drain replay-mode projection, time
/// wakes, and intent dispatch to a fixpoint. Returns counters, or an error if
/// replay produced network rows before the barrier.
pub fn run_replay(
    store: &Store,
    projector: &dyn Projector,
    routes: &'static [HandlerRoute],
    allowed_tables: &[TableName],
    fact_admission: Option<FactAdmissionFn>,
    replay_time_wakes: &[DaemonTimeWake],
    order: ReplayOrder,
) -> Result<ReplayReport, String> {
    let mut report = ReplayReport {
        dropped_durable_intents: table_count(store, INTENTS)?,
        dropped_local_intents: table_count(store, LOCAL_INTENTS)?,
        ..ReplayReport::default()
    };
    let facts_before = fact_id_set(store)?;

    report.wiped_tables = wipe_derived_state(store)?;
    report.retained_facts = table_count(store, FACTS)?;

    let drive = ReplayDrive::new(
        store,
        projector,
        allowed_tables,
        fact_admission,
        replay_time_wakes,
        routes,
    );
    let mut counters = ReplayCounters::default();
    match order {
        ReplayOrder::Canonical => {
            project_fact::enqueue_retained_facts_for_replay(store)?;
            drive.fixpoint(&mut counters)?;
        }
        ReplayOrder::Reverse | ReplayOrder::Scramble { .. } => {
            for fact_id in ordered_fact_ids(store, order)? {
                project_fact::enqueue_retained_fact_for_replay(store, fact_id)?;
                drive.fixpoint(&mut counters)?;
            }
            // A final fixpoint settles any work left after the last admission.
            drive.fixpoint(&mut counters)?;
        }
    }

    let facts_after = fact_id_set(store)?;
    report.emitted_facts = facts_after.difference(&facts_before).count();
    report.purged_facts = facts_before.difference(&facts_after).count();
    report.projected_facts = counters.projected_facts;
    report.semantic_time_wakes = counters.time_wake_admissions;
    report.replayed_intents = counters.replayed_intents;
    report.standing_time_wakes = table_count(store, TIME_WAKES)?;
    report.context_edges = table_count(store, CONTEXT_EDGES)?;
    report.row_mutations = materialized_row_count(store)?;
    let remaining_queued_work = table_count(store, INTENTS)? + table_count(store, LOCAL_INTENTS)?;
    report.network_rows = table_count(store, OUTBOUND_TABLE)? + table_count(store, INBOUND_TABLE)?;

    if remaining_queued_work > 0 {
        return Err(format!(
            "replay left {remaining_queued_work} queued intent rows after the barrier; replay work did not reach a fixpoint"
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

/// Compute the canonical state digest for the current store.
pub fn state_summary(store: &Store) -> Result<StateSummary, String> {
    let mut areas = Vec::new();
    for summary in store.replay_summary_table_hashes()? {
        areas.push(AreaSummary {
            area: summary.table,
            hash: summary.hash,
            count: summary.count,
        });
    }
    areas.sort_by(|left, right| left.area.cmp(&right.area));

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo:replay-state-summary:v1");
    for area in &areas {
        hasher.update(&(area.area.len() as u64).to_le_bytes());
        hasher.update(area.area.as_bytes());
        hasher.update(&(area.count as u64).to_le_bytes());
        hasher.update(&area.hash);
    }
    Ok(StateSummary {
        state_hash: *hasher.finalize().as_bytes(),
        areas,
    })
}

#[derive(Debug, Clone, Default)]
struct ReplayCounters {
    projected_facts: usize,
    time_wake_admissions: usize,
    replayed_intents: usize,
}

/// Replay-mode work driver over the ordinary projection and dispatch workers.
///
/// It instantiates the ordinary handler routes and passes replay mode through
/// handler context. Projection, time-wake admission, and replay dispatch run to
/// a fixpoint together because each can produce inputs for the others.
struct ReplayDrive<'a> {
    store: &'a Store,
    projector: &'a dyn Projector,
    allowed_tables: &'a [TableName],
    fact_admission: Option<FactAdmissionFn>,
    replay_time_wakes: &'a [DaemonTimeWake],
    handlers: HandlerSet,
}

impl<'a> ReplayDrive<'a> {
    fn new(
        store: &'a Store,
        projector: &'a dyn Projector,
        allowed_tables: &'a [TableName],
        fact_admission: Option<FactAdmissionFn>,
        replay_time_wakes: &'a [DaemonTimeWake],
        routes: &'static [HandlerRoute],
    ) -> Self {
        let handlers = HandlerSet::new(routes);
        Self {
            store,
            projector,
            allowed_tables,
            fact_admission,
            replay_time_wakes,
            handlers,
        }
    }

    fn fixpoint(&self, counters: &mut ReplayCounters) -> Result<(), String> {
        for _ in 0..REPLAY_FIXPOINT_ROUNDS {
            let mut progressed = false;
            progressed |= self.project_to_idle(counters)?;
            progressed |= self.admit_time_wakes(counters)?;
            progressed |= self.project_to_idle(counters)?;
            progressed |= self.dispatch_replay(counters)?;
            if !progressed {
                return Ok(());
            }
        }
        Err("replay did not reach a fixpoint within the round limit".to_string())
    }

    fn project_to_idle(&self, counters: &mut ReplayCounters) -> Result<bool, String> {
        let mut progressed = false;
        loop {
            let progress = project_fact::drain_projection(
                self.store,
                self.projector,
                self.allowed_tables,
                self.fact_admission,
                project_fact::ProjectionDrainScope::Runtime,
                REPLAY_WORK_LIMIT,
            )?;
            counters.projected_facts += progress.projected;
            if progress.projected == 0 {
                break;
            }
            progressed = true;
        }
        Ok(progressed)
    }

    fn admit_time_wakes(&self, counters: &mut ReplayCounters) -> Result<bool, String> {
        let mut admitted = 0;
        for wake in self.replay_time_wakes {
            let Some(end_inclusive) = (wake.end_inclusive)(self.store)? else {
                continue;
            };
            admitted += project_fact::process_due_time_range_for_replay(
                self.store,
                (wake.timeline)(),
                None,
                end_inclusive,
                REPLAY_WORK_LIMIT,
            )?;
        }
        counters.time_wake_admissions += admitted;
        Ok(admitted > 0)
    }

    fn dispatch_replay(&self, counters: &mut ReplayCounters) -> Result<bool, String> {
        let progress = dispatch_intents(
            self.store,
            &self.handlers,
            self.allowed_tables,
            self.fact_admission,
            REPLAY_WORK_LIMIT,
            HandlerMode::Replay,
            RuntimeEffectMode::Replay,
        )?;
        counters.replayed_intents += progress.dispatched;
        Ok(progress.status.progressed)
    }
}

/// Wipe every schema-declared replay-resettable table.
fn wipe_derived_state(store: &Store) -> Result<usize, String> {
    store.clear_replay_reset_tables()
}

/// Compute the fact admission order for the requested replay order.
fn ordered_fact_ids(store: &Store, order: ReplayOrder) -> Result<Vec<FactId>, String> {
    // Canonical admission order: received_at then fact id, matching the pending
    // projection batch ordering used in normal operation.
    let sql = "SELECT f.id
               FROM facts f
               JOIN local_fact_admissions m ON m.fact_id = f.id
               ORDER BY m.received_at, f.id";
    let mut stmt = store
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

fn fact_id_set(store: &Store) -> Result<BTreeSet<FactId>, String> {
    let mut stmt = store
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
fn materialized_row_count(store: &Store) -> Result<usize, String> {
    let mut total = 0;
    for table in store.replay_summary_tables() {
        if RUNTIME_INDEX_TABLES.contains(table) {
            continue;
        }
        total += table_count(store, *table)?;
    }
    Ok(total)
}

fn table_count(store: &Store, table: TableName) -> Result<usize, String> {
    store
        .table_row_count(table)
        .map_err(|err| format!("count {}: {err}", table.as_str()))
}
