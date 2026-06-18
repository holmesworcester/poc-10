//! Generic target runtime.
//!
//! Runtime is the place where the generic core engine becomes an executable
//! protocol instance. Core owns the mechanics: open the database, submit facts and
//! intents, run pending fact projection, admit due time wakes, and dispatch
//! handler work through SQLite-backed queues. Protocol code supplies the schema
//! sources, projector router, handler registry, and row mutation allowlist that
//! make those mechanics meaningful.
//!
//! The runtime does not interpret protocol bytes. It has five jobs:
//!
//! 1. Open a database with core plus protocol schema.
//! 2. Expose SQL-backed queue/status diagnostics.
//! 3. Admit command, host, fact, and intent work into core storage.
//! 4. Drain one bounded queue at a time in the order chosen by daemon/replay.
//! 5. Snapshot, replay, and compare replay-relevant state.
//!
//! Command-authored facts commit before command receipts are returned, and
//! handler output commits only through the dispatch boundary. Those rules make
//! facts, context, rows, and queued work visible in a predictable order
//! regardless of whether work came from a CLI command, a daemon tick, sync, or a
//! protocol handler.
//!
//! This is the facade a protocol host should use when it wants the whole core
//! engine. Runtime holds the concrete database, projector, and protocol
//! description. Daemon and replay choose ordering by calling the named bounded
//! queue steps.

use crate::core::command::AuthoredFacts;
use crate::core::db::{Db, SchemaSource, TableName};
use crate::core::effects::RuntimeEffects;
use crate::core::facts::Fact;
use crate::core::handle_intent::{dispatch_one_intent, HandlerSet, IntentQueue};
use crate::core::intents::Intent;
use crate::core::project_fact::{
    self, FactAdmissionFn, FactRoute, ProjectionSource, Projector, Timeline,
};
use crate::core::schema::{CORE_SCHEMA_SOURCE, INTENTS, LOCAL_INTENTS};
use std::path::Path;

pub use crate::core::handle_intent::{
    HandlerRoute, RecurringIntentBuilder, RecurringIntentContext, RecurringIntentSpec, WorkStatus,
};

/// Factory for the protocol's projector implementation.
pub type ProjectorFactory = fn() -> Box<dyn Projector>;
/// Protocol-owned declarations needed by core's runtime engine.
///
/// The description is static so a runtime instance cannot drift after opening
/// its database. `schema_sources` declare protocol tables, `row_mutation_tables`
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
    db: Db,
    projector: Box<dyn Projector>,
    handlers: HandlerSet,
}

impl Runtime {
    // -------------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------------

    /// Open an in-memory runtime with core and protocol schema sources applied.
    pub fn open_memory(description: &'static RuntimeDescription) -> Result<Self, String> {
        let schema_sources = runtime_schema_sources(description);
        let db = Db::open_memory_with_schema_sources(&schema_sources)
            .map_err(|err| format!("open target memory db: {err}"))?;
        Self::from_db(description, db)
    }

    /// Open a disk-backed runtime with core and protocol schema sources applied.
    pub fn open_disk(
        description: &'static RuntimeDescription,
        path: impl AsRef<Path>,
    ) -> Result<Self, String> {
        let schema_sources = runtime_schema_sources(description);
        let db = Db::open_disk_with_schema_sources(path, &schema_sources)
            .map_err(|err| format!("open target disk db: {err}"))?;
        Self::from_db(description, db)
    }

    fn from_db(description: &'static RuntimeDescription, db: Db) -> Result<Self, String> {
        Ok(Self {
            description,
            db,
            projector: (description.projector)(),
            handlers: HandlerSet::new(description.handlers),
        })
    }

    // -------------------------------------------------------------------------
    // SQL-Backed Runtime State
    // -------------------------------------------------------------------------

    /// Borrow the runtime's database handle.
    ///
    /// This exposes the concrete SQLite-backed database for query helpers and
    /// daemon IO code that must share the same connection-local memory tables as
    /// the runtime. New runtime flows should prefer the typed methods below so
    /// projection and intent ordering stay centralized here.
    pub fn db(&self) -> &Db {
        &self.db
    }

    /// Count projection inputs still waiting in SQL.
    ///
    /// This is queue depth, not fact storage. It includes durable
    /// `pending_projection` rows and volatile `incoming_facts` rows because both
    /// are inputs to fact projection.
    pub fn pending_projection_count(&self) -> usize {
        project_fact::pending_projection_input_count(&self.db)
    }

    /// Count durable plus ephemeral queued intents.
    pub fn pending_intent_count(&self) -> usize {
        let stored = self
            .db
            .table_row_count(INTENTS)
            .expect("runtime intent count should load from database");
        let local = self
            .db
            .table_row_count(LOCAL_INTENTS)
            .expect("runtime local intent count should load from database");
        stored + local
    }

    /// Borrow the declared handler routes for registry diagnostics.
    pub fn handler_routes(&self) -> &'static [HandlerRoute] {
        self.description.handlers
    }

    // -------------------------------------------------------------------------
    // Work Admission
    // -------------------------------------------------------------------------

    /// Admit one fact and mark it pending for projection.
    pub fn submit_fact(&mut self, fact: Fact) -> bool {
        project_fact::submit_fact_with_admission(&self.db, fact, self.description.fact_admission)
            .expect("runtime fact submission should persist")
    }

    /// Admit many facts in one transaction.
    pub fn submit_facts(&mut self, facts: impl IntoIterator<Item = Fact>) -> Result<usize, String> {
        project_fact::submit_facts_with_admission(&self.db, facts, self.description.fact_admission)
    }

    /// Queue durable idempotent work for the protocol handler registry.
    ///
    /// The handler selected by `intent.kind` runs in a later runtime/daemon work
    /// pass. Use `submit_local_intent` for work that is only valid on this
    /// process and should disappear on restart.
    pub fn submit_intent(&mut self, intent: Intent) -> Result<bool, String> {
        crate::core::handle_intent::submit_intent_to_table(&self.db, INTENTS, intent)
    }

    /// Queue ephemeral work for this runtime connection.
    pub fn submit_local_intent(&mut self, intent: Intent) -> Result<bool, String> {
        crate::core::handle_intent::submit_local_intent_to_db(&self.db, intent)
    }

    /// Commit the facts returned by a user-facing command and return its receipt.
    ///
    /// Command receipts are not runtime queue state. They return directly to the CLI
    /// caller after the command's authored facts have been retained and queued
    /// for projection.
    pub fn submit_authored_facts<T>(&mut self, output: AuthoredFacts<T>) -> Result<T, String> {
        project_fact::submit_authored_facts_to_db(
            &self.db,
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
        project_fact::commit_effects::commit_runtime_effects_to_db(
            &self.db,
            &effects,
            self.description.row_mutation_tables,
            self.description.fact_admission,
            false,
            false,
            label,
        )
        .map(|_| ())
    }

    // -------------------------------------------------------------------------
    // Bounded Queue Drains
    // -------------------------------------------------------------------------

    /// Drain at most `limit` durable projection items.
    ///
    /// Runtime owns the bounded loop; `project_fact` owns the one-item
    /// projection transaction. This keeps daemon scheduling visible without
    /// spreading projection commit details outside the projection worker.
    pub fn drain_durable_projection(&mut self, limit: usize) -> Result<WorkStatus, String> {
        self.drain_projection_source(ProjectionSource::Durable, limit)
    }

    /// Drain at most `limit` incoming projection items.
    ///
    /// Incoming facts are process-local intake. The daemon schedules this queue
    /// explicitly after durable projection so readers do not have to inspect
    /// `project_fact` to learn the live projection order.
    pub fn drain_incoming_projection(&mut self, limit: usize) -> Result<WorkStatus, String> {
        self.drain_projection_source(ProjectionSource::Incoming, limit)
    }

    fn drain_projection_source(
        &mut self,
        source: ProjectionSource,
        limit: usize,
    ) -> Result<WorkStatus, String> {
        drain_bounded_work(limit, || {
            project_fact::project_one(
                &self.db,
                self.projector.as_ref(),
                source,
                self.description.row_mutation_tables,
                self.description.fact_admission,
            )
        })
    }

    /// Drain at most `limit` durable intents using the live handler set.
    ///
    /// Runtime owns the bounded loop and yield policy. `handle_intent` owns the
    /// one-row handler transaction.
    pub fn drain_durable_intents(&mut self, limit: usize) -> Result<WorkStatus, String> {
        self.drain_intent_queue(IntentQueue::Durable, limit)
    }

    /// Drain at most `limit` local intents using the live handler set.
    ///
    /// Local retries are rotated to the tail by `handle_intent`. A retry stops
    /// this queue's current bounded pass; the next daemon tick can try the next
    /// local row.
    pub fn drain_local_intents(&mut self, limit: usize) -> Result<WorkStatus, String> {
        self.drain_intent_queue(IntentQueue::Local, limit)
    }

    fn drain_intent_queue(
        &mut self,
        queue: IntentQueue,
        limit: usize,
    ) -> Result<WorkStatus, String> {
        drain_bounded_work(limit, || {
            dispatch_one_intent(
                &self.db,
                &self.handlers,
                queue,
                self.description.row_mutation_tables,
                self.description.fact_admission,
            )
        })
    }

    /// Admit due time wakes as pending projection inputs for one timeline interval.
    ///
    /// Time wake admission is SQL work, but not a projector or handler drain by
    /// itself. The queued owners are projected by a later durable projection pass.
    pub fn process_due_time_range(
        &mut self,
        timeline: Timeline,
        start_exclusive: Option<u64>,
        end_inclusive: u64,
        limit: usize,
    ) -> Result<usize, String> {
        project_fact::process_due_time_range(
            &self.db,
            timeline,
            start_exclusive,
            end_inclusive,
            limit,
        )
    }

    // -------------------------------------------------------------------------
    // Replay and Snapshots
    // -------------------------------------------------------------------------

    /// Run the replay entry point against this runtime's database.
    ///
    /// Replay drops queued intents and other schema-declared non-fact runtime
    /// state, then drains retained facts through replay-mode projection and
    /// handler context until the replay barrier is idle. Replay must not run
    /// network IO, recurring schedules, or operational wall-clock decisions.
    pub fn replay(
        &mut self,
        order: crate::core::replay::ReplayOrder,
    ) -> Result<crate::core::replay::ReplayReport, String> {
        crate::core::replay::run_replay(
            &self.db,
            self.projector.as_ref(),
            self.description.handlers,
            self.description.row_mutation_tables,
            self.description.fact_admission,
            order,
        )
    }

    /// Compute the canonical, order-independent digest of replay-relevant state.
    pub fn state_summary(&self) -> Result<crate::core::replay_check::StateSummary, String> {
        crate::core::replay_check::state_summary(&self.db)
    }

    /// Write a standalone snapshot of this runtime's database to `path`.
    pub fn snapshot_to(&self, path: &Path) -> Result<(), String> {
        self.db.backup_into(path)
    }

    /// Prove replay idempotence and projection-order independence on scratch
    /// copies of this runtime's database.
    ///
    /// Snapshots the live database, then runs the canonical, idempotent, reverse,
    /// and scrambled replay plans against independent scratch databases and
    /// compares their state digests. The live database is never mutated. Scratch
    /// runtimes are opened here in core so protocol CLI hosts never open a database
    /// themselves.
    pub fn replay_check(
        &self,
        scratch_dir: &Path,
    ) -> Result<crate::core::replay_check::ReplayCheckReport, String> {
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
                runtime.replay(*order)?;
            }
            summaries.push(((*name).to_string(), runtime.state_summary()?));
        }

        Ok(crate::core::replay_check::compare_replay_passes(summaries))
    }
}

fn runtime_schema_sources(description: &RuntimeDescription) -> Vec<SchemaSource> {
    let mut sources = Vec::with_capacity(1 + description.schema_sources.len());
    sources.push(CORE_SCHEMA_SOURCE);
    sources.extend_from_slice(description.schema_sources);
    sources
}

fn drain_bounded_work(
    limit: usize,
    mut step: impl FnMut() -> Result<WorkStatus, String>,
) -> Result<WorkStatus, String> {
    // Each runtime drain is a bounded loop over a one-item worker. Idle means the
    // selected queue is empty; retry means a local handler deliberately yielded.
    let mut status = WorkStatus::idle();
    for _ in 0..limit {
        let step_status = step()?;
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
    fn db_handle_reads_store_backed_fact_counts_from_sqlite() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("runtime.db");
        let runtime = Runtime::open_disk(&TEST_RUNTIME, &path).expect("runtime");

        let external_fact = Fact::new(FactScope::Global, 7, b"external".to_vec());
        let mut writer = Runtime::open_disk(&TEST_RUNTIME, &path).expect("writer runtime");
        assert!(writer.submit_fact(external_fact.clone()));

        assert_eq!(
            runtime
                .db()
                .table_row_count(crate::core::schema::FACTS)
                .expect("fact count"),
            1,
            "fact counts should read externally committed facts from SQLite"
        );
    }

    #[test]
    fn pending_projection_count_reports_durable_queue_and_incoming_intake() {
        let mut runtime = Runtime::open_memory(&TEST_RUNTIME).expect("runtime");
        let durable = Fact::new(FactScope::Global, 7, b"durable queued".to_vec());
        let incoming = Fact::new(FactScope::Local, 8, b"incoming queued".to_vec());

        assert!(runtime.submit_fact(durable));
        runtime
            .submit_runtime_effects(
                RuntimeEffects::new().incoming_fact(incoming),
                "stage incoming test fact",
            )
            .expect("stage incoming fact");

        assert_eq!(
            runtime.pending_projection_count(),
            2,
            "pending projection count should include durable queue rows and volatile incoming intake"
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
            runtime
                .db()
                .table_row_count(crate::core::schema::FACTS)
                .expect("fact count"),
            1,
            "command-authored fact should be retained immediately"
        );
        assert_eq!(
            runtime.pending_projection_count(),
            1,
            "command-authored fact should be queued for projection"
        );
        assert_eq!(
            runtime
                .db()
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
            .drain_durable_projection(1)
            .expect("drain one projection");
        assert_eq!(
            projection_runtime.pending_projection_count(),
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
            .drain_durable_intents(1)
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

        let first = runtime
            .drain_durable_intents(8)
            .expect("drain durable intent batch");

        assert!(first.progressed);
        assert_eq!(
            runtime.pending_intent_count(),
            0,
            "the intent should be consumed when its handler output commits"
        );
        assert_eq!(
            runtime.pending_projection_count(),
            1,
            "handler-emitted facts should stay queued for a later projection pass"
        );

        let second = runtime
            .drain_durable_projection(8)
            .expect("drain later durable projection batch");

        assert!(second.progressed);
        assert_eq!(
            runtime.pending_projection_count(),
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
            runtime
                .db()
                .table_row_count(crate::core::schema::FACTS)
                .expect("fact count")
                == 0,
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
