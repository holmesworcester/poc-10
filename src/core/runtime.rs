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
//! the transaction ordering rules: command-authored facts commit before command
//! receipts are returned, projection drains before intent dispatch when queues
//! are being settled, and handler output commits only through the dispatch
//! boundary. Those rules make facts, context, rows, and queued work visible in
//! a predictable order regardless of whether work came from a CLI command, a
//! daemon tick, sync, or a protocol handler.
//!
//! This is the facade a protocol host should use when it wants the whole core
//! engine. Runtime holds the concrete store, projector, and protocol
//! description, and composes the one-item projection and intent workers into
//! command, daemon, and replay ordering.

use crate::core::command::CommandOutput;
use crate::core::facts::Fact;
use crate::core::handle_intent::{dispatch_intents, HandlerSet};
use crate::core::intents::Intent;
use crate::core::project_fact::{
    self, FactAdmissionFn, FactRoute, IntentAdmissionPolicy, Projector, Timeline,
};
use crate::core::schema::{CORE_SCHEMA_SOURCE, INTENTS, LOCAL_INTENTS};
use crate::core::store::persisted_facts;
use crate::core::store::{SchemaSource, Store, TableName};
use std::path::Path;

pub use crate::core::handle_intent::{
    HandlerRoute, RecurringIntentBuilder, RecurringIntentContext, RecurringIntentSpec, WorkStatus,
};

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
    /// Per-fact-type projector routes used for registry diagnostics and
    /// version-manifest checks. Replay policy is projector-owned through
    /// `ProjectionContext::is_replay()`, not a route-table flag.
    pub fact_routes: &'static [FactRoute],
    /// Optional protocol-owned fact admission check run before core stores facts.
    pub fact_admission: Option<FactAdmissionFn>,
    /// Intent handlers this runtime may dispatch.
    pub handlers: &'static [HandlerRoute],
    /// Handler route names a synchronous command should not run.
    pub command_excluded_handlers: &'static [&'static str],
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

    /// Return all persisted facts known to this runtime.
    pub fn facts(&self) -> impl Iterator<Item = Fact> {
        persisted_facts(&self.store)
            .expect("runtime facts should load from store")
            .into_iter()
    }

    /// Count facts currently queued for projection.
    pub fn pending_fact_count(&self) -> usize {
        project_fact::pending_fact_count(&self.store)
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

    /// Borrow the declared handler routes, including replay and recurrence
    /// metadata, for registry diagnostics.
    pub fn handler_routes(&self) -> &'static [HandlerRoute] {
        self.description.handlers
    }

    /// Borrow the handler route names a synchronous command must not run.
    ///
    /// These are the daemon/live transport handlers; the intent-registry
    /// diagnostic reports this as the `command_excluded` policy answer.
    pub fn command_excluded_handlers(&self) -> &'static [&'static str] {
        self.description.command_excluded_handlers
    }

    /// Admit one fact and mark it pending for projection.
    pub fn submit_fact(&mut self, fact: Fact) -> bool {
        project_fact::submit_fact_with_admission(&self.store, fact, self.description.fact_admission)
            .expect("runtime fact submission should persist")
    }

    /// Admit many facts in one transaction.
    pub fn submit_facts(&mut self, facts: impl IntoIterator<Item = Fact>) -> Result<usize, String> {
        project_fact::submit_facts_with_admission(
            &self.store,
            facts,
            self.description.fact_admission,
        )
    }

    /// Remove one fact and its core-owned derived rows.
    pub fn purge_fact(&mut self, fact_id: crate::core::facts::FactId) -> bool {
        project_fact::purge_fact_from_store(&self.store, fact_id)
            .expect("runtime fact purge should persist")
    }

    /// Queue durable idempotent work for the protocol handler registry.
    ///
    /// The handler selected by `intent.kind` may run in a later daemon or
    /// command-safe drain pass. Use `submit_local_intent` for work that is only
    /// valid on this process and should disappear on restart.
    pub fn submit_intent(&mut self, intent: Intent) -> Result<bool, String> {
        crate::core::handle_intent::submit_intent_to_table(&self.store, INTENTS, intent)
    }

    /// Queue ephemeral work for this runtime connection.
    pub fn submit_local_intent(&mut self, intent: Intent) -> Result<bool, String> {
        crate::core::handle_intent::submit_local_intent_to_store(&self.store, intent)
    }

    /// Commit the facts returned by a user-facing command and return its receipt.
    ///
    /// Command receipts are not runtime queue state. They return directly to the CLI
    /// caller after the command's authored facts have been retained and queued
    /// for projection.
    pub fn submit_command_output<T>(&mut self, output: CommandOutput<T>) -> Result<T, String> {
        project_fact::submit_command_output_to_store(
            &self.store,
            output,
            self.description.row_mutation_tables,
            self.description.fact_admission,
            "submit command output",
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
        project_fact::process_projection_until_idle(
            &self.store,
            self.projector.as_ref(),
            self.description.row_mutation_tables,
            self.description.fact_admission,
            max_rounds,
            limit_per_round,
        )
    }

    /// Run one daemon tick's queue order after IO and time wakes have been handled.
    ///
    /// Projection runs before and after intent dispatch because handlers often
    /// emit facts that should become visible before the next quiet sleep.
    pub fn drain_daemon_queues_once(&mut self, limit: usize) -> Result<WorkStatus, String> {
        let mut total = WorkStatus::idle();
        total.merge(project_fact::process_projection_until_idle(
            &self.store,
            self.projector.as_ref(),
            self.description.row_mutation_tables,
            self.description.fact_admission,
            4,
            limit,
        )?);
        total.merge(
            dispatch_intents(
                &self.store,
                &self.handlers,
                self.description.row_mutation_tables,
                self.description.fact_admission,
                limit,
                IntentAdmissionPolicy::All,
            )?
            .status,
        );
        total.merge(project_fact::process_projection_until_idle(
            &self.store,
            self.projector.as_ref(),
            self.description.row_mutation_tables,
            self.description.fact_admission,
            4,
            limit,
        )?);
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
        self.process_work_until_idle(max_rounds, limit_per_round, &self.handlers)
    }

    fn process_work_until_idle(
        &self,
        max_rounds: usize,
        limit_per_round: usize,
        handlers: &HandlerSet,
    ) -> Result<WorkStatus, String> {
        let mut total = WorkStatus::idle();
        for _ in 0..max_rounds {
            total.merge(crate::core::perf_profile::measure_result(
                "projection",
                || {
                    project_fact::process_projection_until_idle(
                        &self.store,
                        self.projector.as_ref(),
                        self.description.row_mutation_tables,
                        self.description.fact_admission,
                        8,
                        limit_per_round,
                    )
                },
            )?);
            let dispatched = crate::core::perf_profile::measure_result("intent_dispatch", || {
                dispatch_intents(
                    &self.store,
                    handlers,
                    self.description.row_mutation_tables,
                    self.description.fact_admission,
                    limit_per_round,
                    IntentAdmissionPolicy::All,
                )
                .map(|progress| progress.status)
            })?;
            total.merge(dispatched);
            if dispatched.is_idle() {
                total.merge(crate::core::perf_profile::measure_result(
                    "projection",
                    || {
                        project_fact::process_projection_until_idle(
                            &self.store,
                            self.projector.as_ref(),
                            self.description.row_mutation_tables,
                            self.description.fact_admission,
                            8,
                            limit_per_round,
                        )
                    },
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
        self.process_work_until_idle(max_rounds, limit_per_round, &handlers)
    }

    pub fn process_due_time_range(
        &mut self,
        timeline: Timeline,
        start_exclusive: Option<u64>,
        end_inclusive: u64,
        limit: usize,
    ) -> Result<usize, String> {
        project_fact::process_due_time_range(
            &self.store,
            timeline,
            start_exclusive,
            end_inclusive,
            limit,
        )
    }

    /// Run the replay entry point against this runtime's store.
    ///
    /// Replay drops queued intents and other schema-declared non-fact runtime
    /// state, then reprojects retained facts to a fixpoint using only
    /// replay-allowed handler routes. The caller supplies the replayable
    /// semantic time-wake timelines; replay must not run network IO, recurring
    /// schedules, or operational wall-clock decisions.
    pub fn replay(
        &mut self,
        replay_time_wakes: &[crate::core::daemon::DaemonTimeWake],
        order: crate::core::replay::ReplayOrder,
    ) -> Result<crate::core::replay::ReplayReport, String> {
        crate::core::replay::run_replay(
            &self.store,
            self.projector.as_ref(),
            self.description.handlers,
            self.description.row_mutation_tables,
            self.description.fact_admission,
            replay_time_wakes,
            order,
        )
    }

    /// Compute the canonical, order-independent digest of replay-relevant state.
    pub fn state_summary(&self) -> Result<crate::core::replay::StateSummary, String> {
        crate::core::replay::state_summary(&self.store)
    }

    /// Write a standalone snapshot of this runtime's store to `path`.
    pub fn snapshot_to(&self, path: &Path) -> Result<(), String> {
        self.store.backup_into(path)
    }

    /// Prove replay idempotence and projection-order independence on scratch
    /// copies of this runtime's store.
    ///
    /// Snapshots the live store, then runs the canonical, idempotent, reverse,
    /// and scrambled replay plans against independent scratch databases and
    /// compares their state digests. The live store is never mutated. Scratch
    /// runtimes are opened here in core so protocol CLI hosts never open a store
    /// themselves.
    pub fn replay_check(
        &self,
        scratch_dir: &Path,
        replay_time_wakes: &[crate::core::daemon::DaemonTimeWake],
    ) -> Result<crate::core::replay::ReplayCheckReport, String> {
        use crate::core::replay::ReplayOrder;

        let snapshot = scratch_dir.join("snapshot.db");
        self.snapshot_to(&snapshot)?;

        // Each plan is a sequence of replay orders run on one scratch copy.
        // `idempotent` runs canonical replay twice to prove a second replay over
        // already-replayed state changes nothing.
        let plans: &[(&str, &[ReplayOrder])] = &[
            ("canonical", &[ReplayOrder::Canonical]),
            (
                "idempotent",
                &[ReplayOrder::Canonical, ReplayOrder::Canonical],
            ),
            ("reverse", &[ReplayOrder::Reverse]),
            ("scramble-1", &[ReplayOrder::Scramble { seed: 1 }]),
            ("scramble-2", &[ReplayOrder::Scramble { seed: 2 }]),
            ("scramble-7", &[ReplayOrder::Scramble { seed: 7 }]),
        ];

        let mut summaries = Vec::with_capacity(plans.len());
        for (name, orders) in plans {
            let path = scratch_dir.join(format!("{name}.db"));
            std::fs::copy(&snapshot, &path)
                .map_err(|err| format!("copy replay-check snapshot for {name}: {err}"))?;
            let mut runtime = Runtime::open_disk(self.description, &path)?;
            for order in *orders {
                runtime.replay(replay_time_wakes, *order)?;
            }
            summaries.push(((*name).to_string(), runtime.state_summary()?));
        }

        Ok(crate::core::replay::compare_replay_passes(summaries))
    }
}

fn runtime_schema_sources(description: &RuntimeDescription) -> Vec<SchemaSource> {
    let mut sources = Vec::with_capacity(1 + description.schema_sources.len());
    sources.push(CORE_SCHEMA_SOURCE);
    sources.extend_from_slice(description.schema_sources);
    sources
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::facts::{Fact, FactScope};
    use crate::core::project_fact::{ProjectionContext, ProjectionOutput};

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
        fact_routes: &[],
        fact_admission: None,
        handlers: &[],
        command_excluded_handlers: &[],
    };

    fn reject_bad_fact(fact: &Fact) -> Result<(), String> {
        if fact.bytes.first().copied() == Some(b'!') {
            Err("bad test fact rejected by admission".to_string())
        } else {
            Ok(())
        }
    }

    const ADMISSION_RUNTIME: RuntimeDescription = RuntimeDescription {
        schema_sources: &[],
        row_mutation_tables: &[],
        projector: noop_projector,
        fact_routes: &[],
        fact_admission: Some(reject_bad_fact),
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
    fn command_output_rejects_facts_that_fail_runtime_admission() {
        let mut runtime = Runtime::open_memory(&ADMISSION_RUNTIME).expect("runtime");
        let rejected = Fact::new(FactScope::Global, 7, b"!bad".to_vec());

        let err = runtime
            .submit_command_output(CommandOutput::new(()).with_facts(vec![rejected.clone()]))
            .expect_err("admission should reject command fact");

        assert!(err.contains("bad test fact rejected by admission"), "{err}");
        assert!(
            !runtime.facts().any(|fact| fact.id == rejected.id),
            "rejected fact must not be persisted"
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
