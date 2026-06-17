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
//! receipts are returned, daemon projection batches run before intent batches,
//! and handler output commits only through the dispatch boundary. Those rules
//! make facts, context, rows, and queued work visible in a predictable order
//! regardless of whether work came from a CLI command, a daemon tick, sync, or a
//! protocol handler.
//!
//! This is the facade a protocol host should use when it wants the whole core
//! engine. Runtime holds the concrete store, projector, and protocol
//! description, and composes the bounded projection and intent workers into
//! command, daemon, and replay ordering.

use crate::core::command::AuthoredFacts;
use crate::core::effects::RuntimeEffects;
use crate::core::facts::Fact;
use crate::core::handle_intent::{dispatch_intents, HandlerSet};
use crate::core::intents::{HandlerMode, Intent};
use crate::core::project_fact::{
    self, FactAdmissionFn, FactRoute, Projector, RuntimeEffectMode, Timeline,
};
use crate::core::schema::{CORE_SCHEMA_SOURCE, INTENTS, LOCAL_INTENTS};
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

    /// Count retained facts without loading their bytes.
    pub fn fact_count(&self) -> usize {
        self.store
            .fact_count()
            .expect("runtime fact count should load from store")
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

    /// Borrow the declared handler routes for registry diagnostics.
    pub fn handler_routes(&self) -> &'static [HandlerRoute] {
        self.description.handlers
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

    /// Queue durable idempotent work for the protocol handler registry.
    ///
    /// The handler selected by `intent.kind` runs in a later runtime/daemon work
    /// pass. Use `submit_local_intent` for work that is only valid on this
    /// process and should disappear on restart.
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
    pub fn submit_authored_facts<T>(&mut self, output: AuthoredFacts<T>) -> Result<T, String> {
        project_fact::submit_authored_facts_to_store(
            &self.store,
            output,
            self.description.row_mutation_tables,
            self.description.fact_admission,
            "submit authored facts",
        )
    }

    /// Commit runtime effects that came from a live host boundary.
    ///
    /// This path is for daemon intake work that is already volatile, such as
    /// accepted network frames. It uses the same validation and atomic effect
    /// commit as projection and intent dispatch, but has no queued input row of
    /// its own to consume.
    pub(crate) fn submit_runtime_effects(
        &mut self,
        effects: RuntimeEffects,
        label: &str,
    ) -> Result<(), String> {
        project_fact::commit_effects::commit_runtime_effects_to_store(
            &self.store,
            &effects,
            self.description.row_mutation_tables,
            self.description.fact_admission,
            label,
        )
        .map(|_| ())
    }

    /// Drain at most `limit` queued projection items once.
    ///
    /// This is the daemon-facing projection step. It advances one bounded batch
    /// and leaves any remaining projection work queued for a later runtime turn.
    pub fn drain_projection_once(&mut self, limit: usize) -> Result<WorkStatus, String> {
        project_fact::drain_projection(
            &self.store,
            self.projector.as_ref(),
            self.description.row_mutation_tables,
            self.description.fact_admission,
            limit,
        )
        .map(|progress| progress.status)
    }

    /// Drain queued intents once using the live handler set.
    ///
    /// Handler-emitted facts are retained and queued durably by dispatch. A
    /// caller that wants those facts projected should run projection in a later
    /// runtime step. This advances at most `limit` intent rows and leaves
    /// remaining work queued.
    pub fn drain_intents_once(&mut self, limit: usize) -> Result<WorkStatus, String> {
        dispatch_intents(
            &self.store,
            &self.handlers,
            self.description.row_mutation_tables,
            self.description.fact_admission,
            limit,
            HandlerMode::Live,
            RuntimeEffectMode::Live,
        )
        .map(|progress| progress.status)
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
    /// state, then drains retained facts through replay-mode projection and
    /// handler context until the replay barrier is idle. The caller supplies the
    /// replayable semantic time-wake timelines; replay must not run network IO,
    /// recurring schedules, or operational wall-clock decisions.
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
    use crate::core::effects::RuntimeEffects;
    use crate::core::facts::{Fact, FactScope};
    use crate::core::intents::{HandlerContext, HandlerResult, IntentHandler, IntentKind};
    use crate::core::project_fact::{ProjectionContext, ProjectionOutput};
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    struct CountingHandler;

    impl IntentHandler for CountingHandler {
        fn handle(&self, _intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
            HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(RuntimeEffects::new())
        }
    }

    struct EmitFactHandler;

    impl IntentHandler for EmitFactHandler {
        fn handle(&self, _intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
            Ok(RuntimeEffects::new().fact(handler_emitted_fact()))
        }
    }

    fn counting_handler() -> Box<dyn IntentHandler> {
        Box::new(CountingHandler)
    }

    fn emit_fact_handler() -> Box<dyn IntentHandler> {
        Box::new(EmitFactHandler)
    }

    fn handler_emitted_fact() -> Fact {
        Fact::new(FactScope::Global, 8, b"handler-emitted".to_vec())
    }

    static HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);

    const COUNTING_HANDLERS: &[HandlerRoute] = &[HandlerRoute {
        intent_kind: "counting",
        factory: counting_handler,
        recurrence: None,
    }];

    const EMIT_FACT_HANDLERS: &[HandlerRoute] = &[HandlerRoute {
        intent_kind: "emit_fact",
        factory: emit_fact_handler,
        recurrence: None,
    }];

    const TEST_RUNTIME: RuntimeDescription = RuntimeDescription {
        schema_sources: &[],
        row_mutation_tables: &[],
        projector: noop_projector,
        fact_routes: &[],
        fact_admission: None,
        handlers: &[],
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
    };

    const HANDLER_RUNTIME: RuntimeDescription = RuntimeDescription {
        schema_sources: &[],
        row_mutation_tables: &[],
        projector: noop_projector,
        fact_routes: &[],
        fact_admission: None,
        handlers: COUNTING_HANDLERS,
    };

    const EMIT_FACT_RUNTIME: RuntimeDescription = RuntimeDescription {
        schema_sources: &[],
        row_mutation_tables: &[],
        projector: noop_projector,
        fact_routes: &[],
        fact_admission: None,
        handlers: EMIT_FACT_HANDLERS,
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
            runtime
                .store()
                .fact_exists(&external_fact.id)
                .expect("fact exists"),
            "fact lookup should read externally committed facts from SQLite"
        );
    }

    #[test]
    fn authored_facts_retain_facts_and_queue_projection_without_incoming() {
        let mut runtime = Runtime::open_memory(&TEST_RUNTIME).expect("runtime");
        let fact = Fact::new(FactScope::Global, 7, b"command-produced-fact".to_vec());

        runtime
            .submit_authored_facts(AuthoredFacts::new(()).with_facts(vec![fact.clone()]))
            .expect("submit authored facts");

        assert_eq!(
            runtime.store().fact(&fact.id).expect("load fact"),
            Some(fact.clone()),
            "command-authored fact should be retained immediately"
        );
        assert_eq!(
            runtime.pending_fact_count(),
            1,
            "command-authored fact should be queued for projection"
        );
        assert_eq!(
            runtime
                .store()
                .table_row_count(crate::core::schema::INCOMING_FACTS)
                .expect("incoming count"),
            0,
            "command-authored facts should not pass through incoming intake"
        );
    }

    #[test]
    fn runtime_queue_drains_respect_one_batch_limit_each() {
        HANDLER_CALLS.store(0, Ordering::SeqCst);
        let mut projection_runtime = Runtime::open_memory(&TEST_RUNTIME).expect("runtime");
        projection_runtime
            .submit_facts([
                Fact::new(FactScope::Global, 7, b"first".to_vec()),
                Fact::new(FactScope::Global, 7, b"second".to_vec()),
            ])
            .expect("submit facts");

        projection_runtime
            .drain_projection_once(1)
            .expect("drain one projection");
        assert_eq!(
            projection_runtime.pending_fact_count(),
            1,
            "one projection batch should process at most its limit"
        );

        let mut intent_runtime = Runtime::open_memory(&HANDLER_RUNTIME).expect("runtime");
        for key in [b"one".to_vec(), b"two".to_vec()] {
            intent_runtime
                .submit_intent(Intent::new(
                    IntentKind::new("counting").expect("intent kind"),
                    key,
                    Vec::new(),
                ))
                .expect("submit intent");
        }

        intent_runtime
            .drain_intents_once(1)
            .expect("drain one intent");
        assert_eq!(
            HANDLER_CALLS.load(Ordering::SeqCst),
            1,
            "one intent batch should dispatch at most its limit"
        );
        assert_eq!(intent_runtime.pending_intent_count(), 1);
    }

    #[test]
    fn intent_drain_leaves_handler_emitted_facts_for_later_projection() {
        let mut runtime = Runtime::open_memory(&EMIT_FACT_RUNTIME).expect("runtime");
        runtime
            .submit_intent(Intent::new(
                IntentKind::new("emit_fact").expect("intent kind"),
                b"one".to_vec(),
                Vec::new(),
            ))
            .expect("submit intent");

        let first = runtime.drain_intents_once(8).expect("drain intent batch");

        assert!(first.progressed);
        assert_eq!(
            runtime.pending_intent_count(),
            0,
            "the intent should be consumed when its handler output commits"
        );
        assert_eq!(
            runtime.pending_fact_count(),
            1,
            "handler-emitted facts should stay queued for a later projection pass"
        );

        let second = runtime
            .drain_projection_once(8)
            .expect("drain later projection batch");

        assert!(second.progressed);
        assert_eq!(
            runtime.pending_fact_count(),
            0,
            "the later projection batch should project the previously emitted fact"
        );
    }

    #[test]
    fn authored_facts_reject_facts_that_fail_runtime_admission() {
        let mut runtime = Runtime::open_memory(&ADMISSION_RUNTIME).expect("runtime");
        let rejected = Fact::new(FactScope::Global, 7, b"!bad".to_vec());

        let err = runtime
            .submit_authored_facts(AuthoredFacts::new(()).with_facts(vec![rejected.clone()]))
            .expect_err("admission should reject command fact");

        assert!(err.contains("bad test fact rejected by admission"), "{err}");
        assert!(
            !runtime
                .store()
                .fact_exists(&rejected.id)
                .expect("fact exists"),
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
