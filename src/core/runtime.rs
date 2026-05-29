//! Generic target runtime.
//!
//! Runtime is the place where the generic core engine becomes an executable
//! protocol instance. Core owns the mechanics: open the store, submit facts and
//! intents, run pending fact projection, admit due time wakes, and dispatch
//! handler work through SQLite-backed queues. Protocol code supplies the schema
//! sources, projector router, handler registry, and row mutation allowlist that
//! make those mechanics meaningful.
//!
//! The runtime does not interpret protocol bytes. It schedules work and holds
//! the transaction ordering rules: command effects commit before command
//! receipts are returned, projection drains before intent dispatch when queues
//! are being settled, and handler output commits only through the dispatch
//! boundary. Those rules make facts, context, rows, and queued work visible in
//! a predictable order regardless of whether work came from a CLI command, a
//! daemon tick, sync, or a protocol handler.
//!
//! This is the facade a protocol host should use when it wants the whole core
//! engine. If code wants to change projection scheduling, intent queue
//! dispatch, command-safe handler filtering, daemon queue draining, or due-time
//! processing, this file is the place that composes those pieces. The pieces
//! themselves stay in `pipeline`, `fact_store`, `store`, and protocol modules.

use crate::core::command_context::{CommandClock, CommandContext, CommandOutput, IdentityVault};
use crate::core::context::ContextOffer;
use crate::core::fact_store::persisted_facts;
use crate::core::facts::{Fact, FactId};
use crate::core::intents::{Intent, IntentHandler};
use crate::core::pipeline;
use crate::core::projectors::{Projector, Timeline};
use crate::core::schema::{
    CONTEXT_EDGES, CORE_SCHEMA_SOURCE, EPHEMERAL_PROJECTION_INPUTS, INTENTS, LOCAL_INTENTS,
    PENDING_PROJECTION, PENDING_TIME_RANGES, TIME_WAKES,
};
use crate::core::store::{
    quoted_table_name, quoted_table_name_str, SchemaSource, Store, TableName,
};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

pub use crate::core::pipeline::WorkStatus;

/// Factory for the protocol's projector implementation.
pub type ProjectorFactory = fn() -> Box<dyn Projector>;
/// Protocol-owned declarations needed by core's runtime engine.
///
/// The description is static so a runtime instance cannot drift after opening
/// its store. `schema_sources` declare protocol tables, `row_mutation_tables`
/// is the allowlist for effects, `projector` defines projection, and `handlers`
/// define the queued work core may dispatch.
#[derive(Clone, Copy)]
pub struct RuntimeDescription {
    /// Protocol table declarations appended after the core schema.
    pub schema_sources: &'static [SchemaSource],
    /// Tables protocol effects are allowed to mutate.
    pub row_mutation_tables: &'static [TableName],
    /// Factory for the projector router.
    pub projector: ProjectorFactory,
    /// Intent handlers this runtime may dispatch.
    pub handlers: &'static [HandlerRoute],
    /// Handler route names a synchronous command should not run.
    pub command_excluded_handlers: &'static [&'static str],
}

/// Factory for one protocol intent handler.
pub type HandlerFactory = fn() -> Box<dyn IntentHandler>;
/// Factory for one live recurring intent instance.
pub type RecurringIntentFactory = fn(&Store, u64) -> Result<Option<Intent>, String>;

/// Live-only recurring work declared beside a handler route.
#[derive(Debug, Clone, Copy)]
pub struct RecurringIntentSpec {
    /// Delay before the first daemon fire after startup.
    pub initial_delay_ms: u64,
    /// Recurring interval after the first fire.
    pub interval_ms: u64,
    /// Build the local intent for this tick. Returning `None` skips the tick.
    pub build_intent: RecurringIntentFactory,
}

/// One handler route in the protocol registry.
///
/// `name` is a human-facing route name used for exclusion lists. `intent_kind`
/// is the queue routing key that selects this handler for both durable and
/// ephemeral intents. Replay and recurrence metadata make the upgrade/replay
/// boundary explicit: core can rebuild derived state with replay-safe handlers
/// while refusing live network or scheduler work until replay finishes.
#[derive(Debug, Clone, Copy)]
pub struct HandlerRoute {
    /// Human-facing route name used for exclusion lists.
    pub name: &'static str,
    /// Intent kind handled by this route.
    pub intent_kind: &'static str,
    /// Handler factory.
    pub factory: HandlerFactory,
    /// Whether this route may dispatch before the replay barrier completes.
    pub runs_during_replay: bool,
    /// Whether this route can perform network IO.
    pub performs_network_io: bool,
    /// Optional live recurring schedule.
    pub recurrence: Option<RecurringIntentSpec>,
}

/// Instantiated handlers for one runtime pass.
///
/// The set owns concrete handler values so dispatch can borrow trait objects
/// without rebuilding them for every queued row. Command processing builds a
/// filtered set to avoid daemon/network side effects.
struct HandlerSet {
    entries: Vec<HandlerEntry>,
}

struct HandlerEntry {
    intent_kind: &'static str,
    handler: Box<dyn IntentHandler>,
}

impl HandlerSet {
    /// Instantiate all declared routes.
    pub fn new(routes: &'static [HandlerRoute]) -> Self {
        Self::new_where(routes, |_| true)
    }

    /// Instantiate routes accepted by `include`.
    pub fn new_where(
        routes: &'static [HandlerRoute],
        include: impl Fn(&HandlerRoute) -> bool,
    ) -> Self {
        Self {
            entries: routes
                .iter()
                .filter(|route| include(route))
                .map(|route| HandlerEntry {
                    intent_kind: route.intent_kind,
                    handler: (route.factory)(),
                })
                .collect(),
        }
    }

    /// Instantiate every route except the protocol-declared command exclusions.
    pub fn new_excluding(routes: &'static [HandlerRoute], excluded_names: &[&str]) -> Self {
        Self::new_where(routes, |route| !excluded_names.contains(&route.name))
    }

    /// Instantiate only replay-safe routes.
    pub fn new_replay(routes: &'static [HandlerRoute]) -> Self {
        Self::new_where(routes, |route| route.runs_during_replay)
    }

    fn intent_kinds(&self) -> Vec<&'static str> {
        self.entries.iter().map(|entry| entry.intent_kind).collect()
    }

    fn handler_for_kind(&self, kind: &str) -> Option<&dyn IntentHandler> {
        self.entries
            .iter()
            .find(|entry| entry.intent_kind == kind)
            .map(|entry| entry.handler.as_ref())
    }

    pub(crate) fn dispatch(
        &self,
        store: &Store,
        allowed_tables: &[TableName],
        limit: usize,
    ) -> Result<WorkStatus, String> {
        let mut total = WorkStatus::idle();
        let kinds = self.intent_kinds();
        let mut retried_local = BTreeSet::<(String, Vec<u8>)>::new();
        for _ in 0..limit {
            let Some(queued) = pipeline::next_queued_intent(store, &kinds)? else {
                break;
            };
            let kind = queued.intent.kind.as_str();
            let local_retry_key = if queued.table == LOCAL_INTENTS {
                Some((kind.to_owned(), queued.intent.key.clone()))
            } else {
                None
            };
            if local_retry_key
                .as_ref()
                .is_some_and(|key| retried_local.contains(key))
            {
                break;
            }
            let handler = self
                .handler_for_kind(kind)
                .ok_or_else(|| format!("no handler registered for intent kind {kind}"))?;
            let status = pipeline::dispatch_queued_intent(handler, store, allowed_tables, queued)?;
            total.merge(status);
            if status.retried {
                if let Some(key) = local_retry_key {
                    retried_local.insert(key);
                    continue;
                }
                break;
            }
        }
        Ok(total)
    }
}

/// Runtime for one concrete protocol description.
///
/// `Runtime` owns a single SQLite connection. All durable and memory tables,
/// projection, and dispatch operations happen through that handle so transaction
/// boundaries stay visible and ephemeral tables are actually local to this
/// runtime instance.
pub struct Runtime {
    description: &'static RuntimeDescription,
    store: Store,
    projector: Box<dyn Projector>,
    handlers: HandlerSet,
}

/// Fact admission order used by the replay entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayOrder {
    /// Stored canonical fact order.
    Canonical,
    /// Reverse of the stored canonical fact order.
    Reverse,
    /// Deterministically shuffled order.
    Scramble { seed: u64 },
}

/// Replay command options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayOptions {
    /// Fact admission order.
    pub order: ReplayOrder,
    /// Maximum replay fixpoint rounds.
    pub max_rounds: usize,
    /// Maximum work items handled per bounded stage.
    pub limit_per_round: usize,
}

impl Default for ReplayOptions {
    fn default() -> Self {
        Self {
            order: ReplayOrder::Canonical,
            max_rounds: 64,
            limit_per_round: 4096,
        }
    }
}

/// Counters reported by the replay entry point.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplayReport {
    pub retained_facts: usize,
    pub dropped_intents: usize,
    pub dropped_local_intents: usize,
    pub wiped_tables: usize,
    pub projected_facts: usize,
    pub replay_allowed_intents: usize,
    pub blocked_live_only_intents: usize,
    pub pending_facts: usize,
    pub pending_intents: usize,
}

/// Replay-check output for scratch snapshot passes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayCheckReport {
    pub state_hash: String,
    pub checked_passes: usize,
}

impl Runtime {
    /// Open an in-memory runtime with core and protocol schema sources applied.
    pub fn open_memory(description: &'static RuntimeDescription) -> Result<Self, String> {
        let schema_sources = runtime_schema_sources(description);
        let store = Store::open_memory_with_schema_sources(&schema_sources)
            .map_err(|err| format!("open target memory store: {err}"))?;
        Self::from_store(description, store)
    }

    /// Open a disk-backed runtime with core and protocol schema sources applied.
    pub fn open_disk(
        description: &'static RuntimeDescription,
        path: impl AsRef<Path>,
    ) -> Result<Self, String> {
        let schema_sources = runtime_schema_sources(description);
        let store = Store::open_disk_with_schema_sources(path, &schema_sources)
            .map_err(|err| format!("open target disk store: {err}"))?;
        Self::from_store(description, store)
    }

    fn from_store(description: &'static RuntimeDescription, store: Store) -> Result<Self, String> {
        Ok(Self {
            description,
            store,
            projector: (description.projector)(),
            handlers: HandlerSet::new(description.handlers),
        })
    }

    /// Borrow the runtime's store handle.
    ///
    /// This exposes the concrete SQLite-backed store for query helpers and
    /// daemon IO code that must share the same connection-local memory tables as
    /// the runtime. New runtime flows should prefer the typed methods below so
    /// projection and intent ordering stay centralized here.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// Borrow the static handler route declarations.
    pub fn handler_routes(&self) -> &'static [HandlerRoute] {
        self.description.handlers
    }

    /// Borrow the static runtime description.
    pub fn description(&self) -> &'static RuntimeDescription {
        self.description
    }

    /// Build a stable digest of replay-relevant state.
    pub fn state_summary(&self) -> Result<crate::core::state_summary::StateSummary, String> {
        crate::core::state_summary::summarize(self.description, &self.store)
    }

    /// Return all persisted facts known to this runtime.
    pub fn facts(&self) -> impl Iterator<Item = Fact> {
        persisted_facts(&self.store)
            .expect("runtime facts should load from store")
            .into_iter()
    }

    /// Count facts currently queued for projection.
    pub fn pending_fact_count(&self) -> usize {
        self.store
            .table_row_count(PENDING_PROJECTION)
            .expect("runtime pending fact count should load from store")
            + self
                .store
                .table_row_count(EPHEMERAL_PROJECTION_INPUTS)
                .expect("runtime ephemeral projection count should load from store")
    }

    /// Count durable plus ephemeral queued intents.
    pub fn pending_intent_count(&self) -> usize {
        let stored = self
            .store
            .table_row_count(INTENTS)
            .expect("runtime intent count should load from store");
        let local = self
            .store
            .table_row_count(LOCAL_INTENTS)
            .expect("runtime local intent count should load from store");
        stored + local
    }

    /// Build the narrow command context for a user-facing command.
    pub fn command_context<'a>(
        &'a self,
        clock: &'a dyn CommandClock,
        vault: &'a dyn IdentityVault,
    ) -> CommandContext<'a> {
        CommandContext::new(&self.store, clock, vault)
    }

    /// Admit one fact and mark it pending for projection.
    pub fn submit_fact(&mut self, fact: Fact) -> bool {
        pipeline::submit_fact_to_store(&self.store, fact)
            .expect("runtime fact submission should persist")
    }

    /// Admit many facts in one transaction.
    pub fn submit_facts(&mut self, facts: impl IntoIterator<Item = Fact>) -> Result<usize, String> {
        pipeline::submit_facts_to_store(&self.store, facts)
    }

    /// Remove one fact and its core-owned derived rows.
    pub fn purge_fact(&mut self, fact_id: crate::core::facts::FactId) -> bool {
        pipeline::purge_fact_from_store(&self.store, fact_id)
            .expect("runtime fact purge should persist")
    }

    pub(crate) fn commit_projected_context_offers(
        &self,
        offers: &[ContextOffer],
        completed_fact_ids: &[FactId],
    ) -> Result<usize, String> {
        pipeline::commit_projected_context_offers(&self.store, offers, completed_fact_ids)
    }

    /// Queue durable idempotent work for the protocol handler registry.
    ///
    /// The handler selected by `intent.kind` may run in a later daemon or
    /// command-safe drain pass. Use `submit_local_intent` for work that is only
    /// valid on this process and should disappear on restart.
    pub fn submit_intent(&mut self, intent: Intent) -> Result<bool, String> {
        pipeline::submit_intent_to_store(&self.store, intent)
    }

    /// Queue ephemeral work for this runtime connection.
    pub fn submit_local_intent(&mut self, intent: Intent) -> Result<bool, String> {
        pipeline::submit_local_intent_to_store(&self.store, intent)
    }

    /// Commit the effects returned by a user-facing command and return its receipt.
    ///
    /// Command receipts are not pipeline state. They return directly to the CLI
    /// caller after the command's facts, rows, and intents have been committed.
    pub fn submit_command_output<T>(&mut self, output: CommandOutput<T>) -> Result<T, String> {
        let (receipt, effects) = output.into_parts();
        pipeline::commit_pipeline_effects_to_store(
            &self.store,
            &effects,
            self.description.row_mutation_tables,
            "submit command output",
        )?;
        Ok(receipt)
    }

    fn process_projection_work(
        &mut self,
        limit: usize,
    ) -> Result<pipeline::ProjectionProgress, String> {
        pipeline::drain_pending_projection(
            self.projector.as_ref(),
            &self.store,
            self.description.row_mutation_tables,
            limit,
        )
    }

    /// Drain pending projection until no projection work remains or rounds expire.
    ///
    /// Each round processes at most `limit_per_round` facts, and newly emitted
    /// context may enqueue more pending facts. Callers use this when they need
    /// projection-visible state to settle without dispatching intent handlers.
    pub fn process_projection_until_idle(
        &mut self,
        max_rounds: usize,
        limit_per_round: usize,
    ) -> Result<WorkStatus, String> {
        let mut total = WorkStatus::idle();
        for _ in 0..max_rounds {
            let progress = self.process_projection_work(limit_per_round)?;
            total.merge(progress.status);
            if progress.projected == 0 && self.pending_fact_count() == 0 {
                return Ok(total);
            }
        }
        Err("projection work did not become idle within the round limit".to_string())
    }

    /// Dispatch queued intents using the full protocol handler set.
    pub fn dispatch_intents(&mut self, limit: usize) -> Result<WorkStatus, String> {
        self.dispatch_with_handlers(&self.handlers, limit)
    }

    /// Dispatch queued intents that are explicitly safe during replay.
    pub fn dispatch_replay_intents(&mut self, limit: usize) -> Result<WorkStatus, String> {
        let handlers = HandlerSet::new_replay(self.description.handlers);
        self.dispatch_with_handlers(&handlers, limit)
    }

    /// Run one daemon tick's queue order after IO and time wakes have been handled.
    ///
    /// Projection runs before and after intent dispatch because handlers often
    /// emit facts that should become visible before the next quiet sleep.
    pub fn drain_daemon_queues_once(&mut self, limit: usize) -> Result<WorkStatus, String> {
        let mut total = WorkStatus::idle();
        total.merge(self.process_projection_until_idle(4, limit)?);
        total.merge(self.dispatch_intents(limit)?);
        total.merge(self.process_projection_until_idle(4, limit)?);
        Ok(total)
    }

    /// Settle all projection and intent work using the protocol's full handler
    /// set. This is for internal runtime workflows; synchronous CLI commands
    /// should usually call `process_command_work_until_idle` so daemon/network
    /// effects remain daemon-owned.
    pub fn process_all_work_until_idle(
        &mut self,
        max_rounds: usize,
        limit_per_round: usize,
    ) -> Result<WorkStatus, String> {
        self.process_work_until_idle(max_rounds, limit_per_round, None)
    }

    fn dispatch_with_handlers(
        &self,
        handlers: &HandlerSet,
        limit: usize,
    ) -> Result<WorkStatus, String> {
        handlers.dispatch(&self.store, self.description.row_mutation_tables, limit)
    }

    fn process_work_until_idle(
        &mut self,
        max_rounds: usize,
        limit_per_round: usize,
        handlers: Option<&HandlerSet>,
    ) -> Result<WorkStatus, String> {
        let mut total = WorkStatus::idle();
        for _ in 0..max_rounds {
            total.merge(crate::core::perf_profile::measure_result(
                "projection",
                || self.process_projection_until_idle(8, limit_per_round),
            )?);
            let dispatched = crate::core::perf_profile::measure_result("intent_dispatch", || {
                self.dispatch_with_handlers(handlers.unwrap_or(&self.handlers), limit_per_round)
            })?;
            total.merge(dispatched);
            if dispatched.is_idle() {
                total.merge(crate::core::perf_profile::measure_result(
                    "projection",
                    || self.process_projection_until_idle(8, limit_per_round),
                )?);
                return Ok(total);
            }
        }
        Ok(total)
    }

    /// Settle work that a synchronous CLI command should be allowed to observe.
    ///
    /// Protocols declare effectful daemon/network handlers as command-excluded
    /// routes. The command host can then ask runtime to finish local projection
    /// and non-effect intent work without knowing the pending-fact, context
    /// change, or intent pipeline schedule.
    pub fn process_command_work_until_idle(
        &mut self,
        max_rounds: usize,
        limit_per_round: usize,
    ) -> Result<WorkStatus, String> {
        let handlers = HandlerSet::new_excluding(
            self.description.handlers,
            self.description.command_excluded_handlers,
        );
        self.process_work_until_idle(max_rounds, limit_per_round, Some(&handlers))
    }

    /// Wipe derived state, replay retained facts, and dispatch replay-safe work.
    pub fn replay(&mut self, options: ReplayOptions) -> Result<ReplayReport, String> {
        let mut report = ReplayReport::default();
        let dropped = self.clear_intent_queues()?;
        report.dropped_intents += dropped.0;
        report.dropped_local_intents += dropped.1;
        report.wiped_tables = self.wipe_derived_state()?;

        let mut facts = persisted_facts(&self.store)?;
        report.retained_facts = facts.len();
        order_replay_facts(&mut facts, options.order);

        for fact in facts {
            self.mark_fact_pending(fact.id)?;
            let status =
                self.process_replay_work_until_idle(options.max_rounds, options.limit_per_round)?;
            report.projected_facts += status.projected_facts;
            report.replay_allowed_intents += status.replay_allowed_intents;
        }

        let status =
            self.process_replay_work_until_idle(options.max_rounds, options.limit_per_round)?;
        report.projected_facts += status.projected_facts;
        report.replay_allowed_intents += status.replay_allowed_intents;
        let blocked = self.clear_replay_blocked_intents()?;
        report.blocked_live_only_intents += blocked.0 + blocked.1;
        report.pending_facts = self.pending_fact_count();
        report.pending_intents = self.pending_intent_count();
        Ok(report)
    }

    /// Verify replay idempotence and ordering independence on scratch snapshots.
    pub fn replay_check(&self, db_path: &Path) -> Result<ReplayCheckReport, String> {
        let canonical_path = replay_snapshot_path(db_path, "canonical")?;
        self.vacuum_into(&canonical_path)?;
        let mut canonical = Runtime::open_disk(self.description, &canonical_path)?;
        canonical.replay(ReplayOptions::default())?;
        let baseline = canonical.state_summary()?;
        canonical.replay(ReplayOptions::default())?;
        let idempotent = canonical.state_summary()?;
        compare_summary_hashes("idempotent", &baseline, &idempotent)?;

        let mut checked_passes = 2usize;
        for (label, order) in [
            ("reverse", ReplayOrder::Reverse),
            ("scramble_1", ReplayOrder::Scramble { seed: 1 }),
            ("scramble_2", ReplayOrder::Scramble { seed: 2 }),
        ] {
            let path = replay_snapshot_path(db_path, label)?;
            self.vacuum_into(&path)?;
            let mut runtime = Runtime::open_disk(self.description, &path)?;
            runtime.replay(ReplayOptions {
                order,
                ..ReplayOptions::default()
            })?;
            let summary = runtime.state_summary()?;
            compare_summary_hashes(label, &baseline, &summary)?;
            checked_passes += 1;
            remove_snapshot(&path);
        }
        remove_snapshot(&canonical_path);

        Ok(ReplayCheckReport {
            state_hash: baseline.state_hash,
            checked_passes,
        })
    }

    fn vacuum_into(&self, path: &Path) -> Result<(), String> {
        remove_snapshot(path);
        let path_text = path
            .to_str()
            .ok_or_else(|| "snapshot path must be UTF-8".to_string())?;
        self.store
            .conn()
            .execute("VACUUM INTO ?1", [path_text])
            .map(|_| ())
            .map_err(|err| format!("create replay snapshot: {err}"))
    }

    fn process_replay_work_until_idle(
        &mut self,
        max_rounds: usize,
        limit_per_round: usize,
    ) -> Result<ReplayWorkStatus, String> {
        let handlers = HandlerSet::new_replay(self.description.handlers);
        let mut total = ReplayWorkStatus::default();
        for _ in 0..max_rounds {
            let progress = self.process_projection_work(limit_per_round)?;
            total.projected_facts += progress.projected;
            total.status.merge(progress.status);

            let before = self.replay_allowed_intent_count()?;
            let dispatched = self.dispatch_with_handlers(&handlers, limit_per_round)?;
            let after = self.replay_allowed_intent_count()?;
            total.replay_allowed_intents += before.saturating_sub(after);
            total.status.merge(dispatched);

            let progress = self.process_projection_work(limit_per_round)?;
            total.projected_facts += progress.projected;
            total.status.merge(progress.status);

            if self.pending_fact_count() == 0
                && self.replay_allowed_intent_count()? == 0
                && !total.status.retried
            {
                return Ok(total);
            }
        }
        Err("replay work did not become idle within the round limit".to_string())
    }

    fn replay_allowed_intent_count(&self) -> Result<usize, String> {
        let allowed = self
            .description
            .handlers
            .iter()
            .filter(|route| route.runs_during_replay)
            .map(|route| route.intent_kind)
            .collect::<Vec<_>>();
        intent_count_for_kinds(&self.store, &allowed)
    }

    fn clear_intent_queues(&self) -> Result<(usize, usize), String> {
        self.store
            .write_transaction(|tx| {
                let durable = tx.conn().execute("DELETE FROM intents", [])?;
                let local = tx.conn().execute("DELETE FROM local_intents", [])?;
                Ok((durable, local))
            })
            .map_err(|err| format!("clear intent queues: {err}"))
    }

    fn clear_replay_blocked_intents(&self) -> Result<(usize, usize), String> {
        let live_only = self
            .description
            .handlers
            .iter()
            .filter(|route| !route.runs_during_replay)
            .map(|route| route.intent_kind)
            .collect::<Vec<_>>();
        delete_intents_for_kinds(&self.store, &live_only)
    }

    fn wipe_derived_state(&self) -> Result<usize, String> {
        let mut tables = BTreeSet::<&'static str>::new();
        for table in [
            CONTEXT_EDGES,
            TIME_WAKES,
            PENDING_PROJECTION,
            PENDING_TIME_RANGES,
            EPHEMERAL_PROJECTION_INPUTS,
        ] {
            tables.insert(table.as_str());
        }
        for table in self.description.row_mutation_tables {
            tables.insert(table.as_str());
        }
        for source in self.description.schema_sources {
            for table in source.row_tables {
                tables.insert(table.as_str());
            }
        }
        tables.remove(INTENTS.as_str());
        tables.remove(LOCAL_INTENTS.as_str());

        self.store
            .write_transaction(|tx| {
                for table in &tables {
                    let table = quoted_table_name_str(table)?;
                    tx.conn().execute(&format!("DELETE FROM {table}"), [])?;
                }
                Ok(tables.len())
            })
            .map_err(|err| format!("wipe replay-derived state: {err}"))
    }

    fn mark_fact_pending(&self, fact_id: FactId) -> Result<(), String> {
        self.store
            .write_transaction(|tx| {
                tx.conn().execute(
                    "INSERT OR IGNORE INTO pending_projection (owner) VALUES (?1)",
                    [fact_id.as_slice()],
                )?;
                Ok(())
            })
            .map_err(|err| format!("mark replay fact pending: {err}"))
    }

    pub fn process_due_time_range(
        &mut self,
        timeline: Timeline,
        start_exclusive: Option<u64>,
        end_inclusive: u64,
        limit: usize,
    ) -> Result<usize, String> {
        pipeline::process_due_time_range(
            &self.store,
            timeline,
            start_exclusive,
            end_inclusive,
            limit,
        )
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ReplayWorkStatus {
    projected_facts: usize,
    replay_allowed_intents: usize,
    status: WorkStatus,
}

fn runtime_schema_sources(description: &RuntimeDescription) -> Vec<SchemaSource> {
    let mut sources = Vec::with_capacity(1 + description.schema_sources.len());
    sources.push(CORE_SCHEMA_SOURCE);
    sources.extend_from_slice(description.schema_sources);
    sources
}

fn order_replay_facts(facts: &mut [Fact], order: ReplayOrder) {
    facts.sort_by_key(|fact| fact.id);
    match order {
        ReplayOrder::Canonical => {}
        ReplayOrder::Reverse => facts.reverse(),
        ReplayOrder::Scramble { seed } => {
            let mut state = seed ^ 0x9e37_79b9_7f4a_7c15;
            for index in (1..facts.len()).rev() {
                state = splitmix64(state);
                facts.swap(index, (state as usize) % (index + 1));
            }
        }
    }
}

fn splitmix64(mut state: u64) -> u64 {
    state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn intent_count_for_kinds(store: &Store, kinds: &[&str]) -> Result<usize, String> {
    if kinds.is_empty() {
        return Ok(0);
    }
    let mut total = 0usize;
    for table in [INTENTS, LOCAL_INTENTS] {
        total += intent_count_for_kinds_in_table(store, table, kinds)?;
    }
    Ok(total)
}

fn intent_count_for_kinds_in_table(
    store: &Store,
    table: TableName,
    kinds: &[&str],
) -> Result<usize, String> {
    let table = quoted_table_name(table).map_err(|err| err.to_string())?;
    let placeholders = (1..=kinds.len())
        .map(|idx| format!("?{idx}"))
        .collect::<Vec<_>>()
        .join(", ");
    store
        .conn()
        .query_row(
            &format!("SELECT COUNT(*) FROM {table} WHERE kind IN ({placeholders})"),
            rusqlite::params_from_iter(kinds.iter().copied()),
            |row| row.get::<_, i64>(0),
        )
        .map(|count| count as usize)
        .map_err(|err| format!("count replay intents: {err}"))
}

fn delete_intents_for_kinds(store: &Store, kinds: &[&str]) -> Result<(usize, usize), String> {
    if kinds.is_empty() {
        return Ok((0, 0));
    }
    store
        .write_transaction(|tx| {
            let durable = delete_intents_for_kinds_in_table(tx, INTENTS, kinds)?;
            let local = delete_intents_for_kinds_in_table(tx, LOCAL_INTENTS, kinds)?;
            Ok((durable, local))
        })
        .map_err(|err| format!("delete replay-blocked intents: {err}"))
}

fn delete_intents_for_kinds_in_table(
    store: &Store,
    table: TableName,
    kinds: &[&str],
) -> rusqlite::Result<usize> {
    let table = quoted_table_name(table)?;
    let placeholders = (1..=kinds.len())
        .map(|idx| format!("?{idx}"))
        .collect::<Vec<_>>()
        .join(", ");
    store.conn().execute(
        &format!("DELETE FROM {table} WHERE kind IN ({placeholders})"),
        rusqlite::params_from_iter(kinds.iter().copied()),
    )
}

fn replay_snapshot_path(db: &Path, label: &str) -> Result<PathBuf, String> {
    let parent = db.parent().unwrap_or_else(|| Path::new("."));
    let file_name = db
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "replay-check db path must have a UTF-8 file name".to_string())?;
    Ok(parent.join(format!(
        ".{file_name}.replay-check.{}.{}.db",
        std::process::id(),
        label
    )))
}

fn remove_snapshot(path: &Path) {
    for candidate in [
        path.to_path_buf(),
        PathBuf::from(format!("{}-wal", path.display())),
        PathBuf::from(format!("{}-shm", path.display())),
    ] {
        let _ = std::fs::remove_file(candidate);
    }
}

fn compare_summary_hashes(
    label: &str,
    expected: &crate::core::state_summary::StateSummary,
    actual: &crate::core::state_summary::StateSummary,
) -> Result<(), String> {
    if expected.state_hash == actual.state_hash {
        return Ok(());
    }
    let mut diffs = Vec::new();
    for expected_area in &expected.areas {
        let Some(actual_area) = actual
            .areas
            .iter()
            .find(|area| area.name == expected_area.name)
        else {
            diffs.push(format!("{} missing in actual", expected_area.name));
            continue;
        };
        if expected_area.count != actual_area.count || expected_area.hash != actual_area.hash {
            diffs.push(format!(
                "{} expected_count={} actual_count={} expected_hash={} actual_hash={}",
                expected_area.name,
                expected_area.count,
                actual_area.count,
                expected_area.hash,
                actual_area.hash
            ));
        }
    }
    Err(format!(
        "replay-check {label} state hash mismatch: expected {} actual {}; {}",
        expected.state_hash,
        actual.state_hash,
        diffs.join("; ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::facts::{Fact, FactScope};
    use crate::core::projectors::{ProjectionContext, ProjectionOutput};

    struct NoopProjector;

    impl Projector for NoopProjector {
        fn project(
            &self,
            _fact: &Fact,
            _context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            Ok(ProjectionOutput::new())
        }
    }

    fn noop_projector() -> Box<dyn Projector> {
        Box::new(NoopProjector)
    }

    const TEST_RUNTIME: RuntimeDescription = RuntimeDescription {
        schema_sources: &[],
        row_mutation_tables: &[],
        projector: noop_projector,
        handlers: &[],
        command_excluded_handlers: &[],
    };

    #[test]
    fn runtime_reads_store_backed_facts_from_sqlite() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("runtime.db");
        let runtime = Runtime::open_disk(&TEST_RUNTIME, &path).expect("runtime");

        let external_fact = Fact::new(FactScope::Global, 7, b"external".to_vec());
        let mut writer = Runtime::open_disk(&TEST_RUNTIME, &path).expect("writer runtime");
        assert!(writer.submit_fact(external_fact.clone()));

        assert!(
            runtime.facts().any(|fact| fact.id == external_fact.id),
            "fact iteration should read externally committed facts from SQLite"
        );
    }

    #[test]
    fn process_due_time_range_rejects_oversized_time_without_panicking() {
        let mut runtime = Runtime::open_memory(&TEST_RUNTIME).expect("runtime");

        let err = runtime
            .process_due_time_range(
                Timeline::new("test_time").expect("timeline"),
                None,
                i64::MAX as u64 + 1,
                1,
            )
            .expect_err("oversized SQLite time should return an error");

        assert!(
            err.contains("SQL value exceeds SQLite integer range"),
            "{err}"
        );
    }
}
