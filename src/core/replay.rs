//! Replay entry point for the generic runtime.
//!
//! Replay rebuilds all derived runtime state from retained facts. It is the
//! mechanism behind a safe upgrade: queued intents are not protocol truth, so a
//! process can drop them, wipe everything projection derives, and reproject the
//! retained facts to recover read-model rows, standing context, semantic time
//! wakes, sync indexes, and key material. The same entry point backs the
//! `replay`/`replay-check` diagnostics, which prove that replay is idempotent
//! and independent of fact projection order.
//!
//! Ownership boundary. Replay reuses the ordinary projection and dispatch
//! workers; it adds three things on top: a derived-state wipe that keeps only
//! the durable inputs (`facts`, `local_fact_admissions`, and the store-local
//! `clock` observation), a projection-order control used by the reverse and
//! scrambled diagnostics, and a replay-mode dispatch filter that runs only
//! handler routes whose `runs_during_replay` flag is set. Live-only intents
//! emitted during replay stay queued and are reported as blocked work; they are
//! never executed before the barrier.
//!
//! Invariants. Replay must not perform network IO or run operational wall-clock
//! decisions. It admits wall-clock context only through the replayable semantic
//! time-wake timelines the caller supplies, and it asserts that no network queue
//! rows were produced. Any network row means a replay-allowed handler crossed
//! the barrier, and replay returns an error instead of a report. Recurring
//! operational schedules are not installed during replay, so they cannot fire.
//!
//! State summary. `state_summary` hashes the replay-relevant protocol state in a
//! canonical, order-independent way: retained facts, standing context, semantic
//! time wakes, and every materialized read-model / sync / connection-maintenance
//! table. It excludes volatile scheduler and socket state — queued intents,
//! pending-projection markers, temp network queues, the admission log, and the
//! clock observation — so two replays that reach the same protocol state always
//! produce the same `state_hash`.

use crate::core::daemon::DaemonTimeWake;
use crate::core::facts::FactId;
use crate::core::intents::IntentHandler;
use crate::core::pipeline;
use crate::core::projectors::Projector;
use crate::core::runtime::HandlerRoute;
use crate::core::store::{quoted_identifier_list, quoted_table_name_str, Store, TableName};
use rusqlite::types::ValueRef;
use std::collections::BTreeSet;

const REPLAY_WORK_LIMIT: usize = 4096;
const REPLAY_FIXPOINT_ROUNDS: usize = 256;

/// Durable inputs that survive a derived-state wipe.
///
/// `facts` and `local_fact_admissions` are the retained source of truth,
/// including retained local facts. `clock` is the store-local trusted-time
/// observation replay reads to admit semantic time wakes deterministically.
const KEEP_TABLES: &[&str] = &["facts", "local_fact_admissions", "clock"];

/// Tables excluded from the state summary because they are volatile scheduler,
/// socket, admission, or transient projection state rather than protocol state.
const VOLATILE_TABLES: &[&str] = &[
    "local_fact_admissions",
    "clock",
    "network_out",
    "network_in",
    "intents",
    "local_intents",
    "pending_projection",
    "pending_time_ranges",
    "ephemeral_projection_inputs",
];

/// Core runtime index tables that are protocol-derived but are not read-model
/// row mutations; counted separately from materialized rows.
const RUNTIME_INDEX_TABLES: &[&str] = &["facts", "context_edges", "time_wakes"];

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
    /// Replay-allowed intents dispatched before the barrier.
    pub replay_allowed_intents: usize,
    /// Standing context edges materialized by replay.
    pub context_edges: usize,
    /// Materialized read-model / sync / connection rows after replay.
    pub row_mutations: usize,
    /// Live-only intents emitted during replay and left queued (blocked).
    pub blocked_live_only_work: usize,
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
/// pending in the requested order, then drain replay-allowed projection, time
/// wakes, and intents to a fixpoint. Returns counters, or an error if replay
/// produced network rows before the barrier.
pub fn run_replay(
    store: &Store,
    projector: &dyn Projector,
    routes: &'static [HandlerRoute],
    allowed_tables: &[TableName],
    replay_time_wakes: &[DaemonTimeWake],
    order: ReplayOrder,
) -> Result<ReplayReport, String> {
    let mut report = ReplayReport {
        dropped_durable_intents: table_count(store, "intents")?,
        dropped_local_intents: table_count(store, "local_intents")?,
        ..ReplayReport::default()
    };
    let facts_before = fact_id_set(store)?;

    report.wiped_tables = wipe_derived_state(store)?;
    report.retained_facts = table_count(store, "facts")?;

    let drive = ReplayDrive::new(store, projector, allowed_tables, replay_time_wakes, routes);
    let mut counters = ReplayCounters::default();
    match order {
        ReplayOrder::Canonical => {
            mark_all_pending(store)?;
            drive.fixpoint(&mut counters)?;
        }
        ReplayOrder::Reverse | ReplayOrder::Scramble { .. } => {
            for fact_id in ordered_fact_ids(store, order)? {
                mark_one_pending(store, &fact_id)?;
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
    report.replay_allowed_intents = counters.replay_allowed_intents;
    report.standing_time_wakes = table_count(store, "time_wakes")?;
    report.context_edges = table_count(store, "context_edges")?;
    report.row_mutations = materialized_row_count(store)?;
    report.blocked_live_only_work =
        table_count(store, "intents")? + table_count(store, "local_intents")?;
    report.network_rows = table_count(store, "network_out")? + table_count(store, "network_in")?;

    if report.network_rows > 0 {
        return Err(format!(
            "replay produced {} network queue rows before the barrier; a replay-allowed handler crossed into network IO",
            report.network_rows
        ));
    }

    Ok(report)
}

/// Compute the canonical state digest for the current store.
pub fn state_summary(store: &Store) -> Result<StateSummary, String> {
    let mut areas = Vec::new();
    for table in summary_tables(store)? {
        let (hash, count) = hash_table(store, &table)?;
        areas.push(AreaSummary {
            area: table,
            hash,
            count,
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
    replay_allowed_intents: usize,
}

/// Replay-mode work driver over the ordinary projection and dispatch workers.
///
/// It instantiates only the replay-allowed handler routes, so live-only intents
/// are never claimed from the queue. Projection, time-wake admission, and
/// replay-allowed dispatch run to a fixpoint together because each can produce
/// inputs for the others.
struct ReplayDrive<'a> {
    store: &'a Store,
    projector: &'a dyn Projector,
    allowed_tables: &'a [TableName],
    replay_time_wakes: &'a [DaemonTimeWake],
    handlers: Vec<(&'static str, Box<dyn IntentHandler>)>,
    kinds: Vec<&'static str>,
}

impl<'a> ReplayDrive<'a> {
    fn new(
        store: &'a Store,
        projector: &'a dyn Projector,
        allowed_tables: &'a [TableName],
        replay_time_wakes: &'a [DaemonTimeWake],
        routes: &'static [HandlerRoute],
    ) -> Self {
        let handlers: Vec<(&'static str, Box<dyn IntentHandler>)> = routes
            .iter()
            .filter(|route| route.runs_during_replay)
            .map(|route| (route.intent_kind, (route.factory)()))
            .collect();
        let kinds = handlers.iter().map(|(kind, _)| *kind).collect();
        Self {
            store,
            projector,
            allowed_tables,
            replay_time_wakes,
            handlers,
            kinds,
        }
    }

    fn handler_for(&self, kind: &str) -> Option<&dyn IntentHandler> {
        self.handlers
            .iter()
            .find(|(route_kind, _)| *route_kind == kind)
            .map(|(_, handler)| handler.as_ref())
    }

    fn fixpoint(&self, counters: &mut ReplayCounters) -> Result<(), String> {
        for _ in 0..REPLAY_FIXPOINT_ROUNDS {
            let mut progressed = false;
            progressed |= self.project_to_idle(counters)?;
            progressed |= self.admit_time_wakes(counters)?;
            progressed |= self.project_to_idle(counters)?;
            progressed |= self.dispatch_replay_allowed(counters)?;
            if !progressed {
                return Ok(());
            }
        }
        Err("replay did not reach a fixpoint within the round limit".to_string())
    }

    fn project_to_idle(&self, counters: &mut ReplayCounters) -> Result<bool, String> {
        let mut progressed = false;
        loop {
            let progress = pipeline::drain_pending_projection(
                self.projector,
                self.store,
                self.allowed_tables,
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
            admitted += pipeline::process_due_time_range(
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

    fn dispatch_replay_allowed(&self, counters: &mut ReplayCounters) -> Result<bool, String> {
        if self.kinds.is_empty() {
            return Ok(false);
        }
        let mut progressed = false;
        for _ in 0..REPLAY_WORK_LIMIT {
            let Some(queued) = pipeline::next_queued_intent(self.store, &self.kinds)? else {
                break;
            };
            let kind = queued.intent.kind.as_str().to_owned();
            let handler = self
                .handler_for(&kind)
                .ok_or_else(|| format!("no replay handler registered for intent kind {kind}"))?;
            let status = pipeline::dispatch_queued_intent(
                handler,
                self.store,
                self.allowed_tables,
                queued,
            )?;
            if status.retried {
                // A replay-allowed handler asked to wait for input that a later
                // projection or dispatch pass should supply. Stop this pass and
                // let the outer fixpoint advance other work first.
                break;
            }
            if !status.progressed {
                break;
            }
            counters.replay_allowed_intents += 1;
            progressed = true;
        }
        Ok(progressed)
    }
}

/// Wipe every derived table, keeping only the durable input tables.
///
/// Enumerating tables rather than naming a fixed list means a newly declared
/// derived table is wiped automatically; only the explicit keep-list survives.
fn wipe_derived_state(store: &Store) -> Result<usize, String> {
    let tables = all_table_names(store)?;
    store
        .write_transaction(|tx| {
            let mut wiped = 0usize;
            for table in &tables {
                if KEEP_TABLES.contains(&table.as_str()) {
                    continue;
                }
                let quoted = quoted_table_name_str(table)?;
                tx.conn().execute(&format!("DELETE FROM {quoted}"), [])?;
                wiped += 1;
            }
            Ok(wiped)
        })
        .map_err(|err| format!("wipe derived state: {err}"))
}

/// Mark every retained fact pending for projection in one statement.
fn mark_all_pending(store: &Store) -> Result<(), String> {
    store
        .conn()
        .execute(
            "INSERT OR IGNORE INTO pending_projection (owner) SELECT id FROM facts",
            [],
        )
        .map(|_| ())
        .map_err(|err| format!("mark retained facts pending: {err}"))
}

/// Mark one retained fact pending for projection.
fn mark_one_pending(store: &Store, fact_id: &FactId) -> Result<(), String> {
    store
        .conn()
        .execute(
            "INSERT OR IGNORE INTO pending_projection (owner) VALUES (?1)",
            rusqlite::params![fact_id.as_slice()],
        )
        .map(|_| ())
        .map_err(|err| format!("mark retained fact pending: {err}"))
}

/// Compute the fact admission order for the requested replay order.
fn ordered_fact_ids(store: &Store, order: ReplayOrder) -> Result<Vec<FactId>, String> {
    // Canonical admission order: received_at then fact id, matching the pending
    // projection batch ordering used in normal operation.
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT f.id
             FROM facts f
             JOIN local_fact_admissions m ON m.fact_id = f.id
             ORDER BY m.received_at, f.id",
        )
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

/// Enumerate every durable and temp table, excluding SQLite internal tables.
fn all_table_names(store: &Store) -> Result<Vec<String>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
             UNION
             SELECT name FROM sqlite_temp_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
             ORDER BY name",
        )
        .map_err(|err| format!("enumerate tables: {err}"))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|err| format!("enumerate tables: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("enumerate tables: {err}"))
}

/// State-summary areas: every table that holds protocol state.
fn summary_tables(store: &Store) -> Result<Vec<String>, String> {
    Ok(all_table_names(store)?
        .into_iter()
        .filter(|name| !VOLATILE_TABLES.contains(&name.as_str()))
        .collect())
}

/// Total materialized read-model / sync / connection rows after replay.
fn materialized_row_count(store: &Store) -> Result<usize, String> {
    let mut total = 0;
    for table in all_table_names(store)? {
        if VOLATILE_TABLES.contains(&table.as_str())
            || RUNTIME_INDEX_TABLES.contains(&table.as_str())
        {
            continue;
        }
        total += table_count(store, &table)?;
    }
    Ok(total)
}

fn table_count(store: &Store, table: &str) -> Result<usize, String> {
    let quoted = quoted_table_name_str(table).map_err(|err| err.to_string())?;
    store
        .conn()
        .query_row(&format!("SELECT COUNT(*) FROM {quoted}"), [], |row| {
            row.get::<_, i64>(0)
        })
        .map(|count| count as usize)
        .map_err(|err| format!("count {table}: {err}"))
}

/// Hash one table's rows canonically, independent of insertion order.
///
/// Rows are ordered by every column so the digest depends only on content, and
/// each cell is serialized with a type tag so distinct SQLite types never alias.
fn hash_table(store: &Store, table: &str) -> Result<([u8; 32], usize), String> {
    let quoted = quoted_table_name_str(table).map_err(|err| err.to_string())?;
    let columns = table_columns(store, &quoted)?;
    let column_list = quoted_identifier_list(&columns).map_err(|err| err.to_string())?;
    let order_list = column_list.clone();
    // An empty column list cannot happen for our tables, but guard the SQL.
    if columns.is_empty() {
        return Err(format!("table {table} has no columns to hash"));
    }

    let mut stmt = store
        .conn()
        .prepare(&format!(
            "SELECT {column_list} FROM {quoted} ORDER BY {order_list}"
        ))
        .map_err(|err| format!("prepare hash scan for {table}: {err}"))?;

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo:replay-area:v1");
    hasher.update(&(table.len() as u64).to_le_bytes());
    hasher.update(table.as_bytes());
    for column in &columns {
        hasher.update(&(column.len() as u64).to_le_bytes());
        hasher.update(column.as_bytes());
    }

    let column_count = columns.len();
    let mut count = 0usize;
    let mut rows = stmt
        .query([])
        .map_err(|err| format!("scan {table}: {err}"))?;
    while let Some(row) = rows
        .next()
        .map_err(|err| format!("scan {table}: {err}"))?
    {
        for index in 0..column_count {
            let value = row
                .get_ref(index)
                .map_err(|err| format!("read {table} cell: {err}"))?;
            hash_cell(&mut hasher, value);
        }
        count += 1;
    }
    Ok((*hasher.finalize().as_bytes(), count))
}

fn hash_cell(hasher: &mut blake3::Hasher, value: ValueRef<'_>) {
    match value {
        ValueRef::Null => hasher.update(&[0u8]),
        ValueRef::Integer(int) => {
            hasher.update(&[1u8]);
            hasher.update(&int.to_le_bytes())
        }
        ValueRef::Real(real) => {
            hasher.update(&[2u8]);
            hasher.update(&real.to_bits().to_le_bytes())
        }
        ValueRef::Text(text) => {
            hasher.update(&[3u8]);
            hasher.update(&(text.len() as u64).to_le_bytes());
            hasher.update(text)
        }
        ValueRef::Blob(blob) => {
            hasher.update(&[4u8]);
            hasher.update(&(blob.len() as u64).to_le_bytes());
            hasher.update(blob)
        }
    };
}

fn table_columns(store: &Store, quoted_table: &str) -> Result<Vec<String>, String> {
    let mut stmt = store
        .conn()
        .prepare(&format!("PRAGMA table_info({quoted_table})"))
        .map_err(|err| format!("read columns: {err}"))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|err| format!("read columns: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("read columns: {err}"))
}
