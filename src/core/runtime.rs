//! Generic target runtime and bounded turn scheduler.
//!
//! Runtime is the place where the protocol-neutral core engine becomes one
//! executable protocol instance. It owns the SQLite connection, core plus
//! protocol schema, fact and intent admission, projection, handler dispatch,
//! time-wake admission, and the bounded order for one runtime turn. Protocol code
//! supplies the schema sources, projector router, handler registry, row mutation
//! allowlist, and live-host declarations that make those mechanics meaningful.
//!
//! `core::app` opens a `Runtime` for either a long-running `start` process or a
//! one-shot command process. `core::daemon` only provides the daemon process
//! lifecycle and live TCP listener. Both hosts enter this file to acquire the
//! runtime-turn lock and run the same bounded turn; `RuntimeTurnHost` says which
//! host resources are present. Daemon-host turns can accept network bytes,
//! dispatch durable handlers, and pump outgoing frames. Local command turns use
//! the same order without a listener, so durable handler dispatch and network
//! adapters are skipped.
//!
//! A turn does not interpret protocol bytes or choose protocol actions. It gives
//! recurring builders a chance to queue local work, drains local and durable
//! queues, stages protocol-classified incoming facts, admits declared time wakes,
//! and leaves semantic decisions to projectors and handlers. Handler-emitted
//! facts remain queued for later projection work, so output ordering is stable
//! regardless of whether work came from a CLI command, daemon tick, sync, or
//! protocol handler.
//!
//! Change this file when runtime storage, queue commit boundaries, or turn order
//! changes. Change `daemon.rs` when long-running process lifecycle changes.
//! Change `app.rs` when CLI routing or command hosting changes.

use crate::core::command::AuthoredFacts;
use crate::core::db::{Db, SchemaSource, TableName};
use crate::core::effects::RuntimeEffects;
use crate::core::facts::Fact;
use crate::core::handle_intent::{handle_one_intent, HandlerSet, IntentQueue};
use crate::core::intents::Intent;
use crate::core::network;
use crate::core::project_fact::{
    self, FactAdmissionFn, FactRoute, IncomingMetadata, ProjectionSource, Projector, Timeline,
};
use crate::core::schema::{CORE_SCHEMA_SOURCE, INTENTS, LOCAL_INTENTS};
use std::fs::{self, File, OpenOptions};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

pub use crate::core::handle_intent::{
    HandlerRoute, RecurringIntentBuilder, RecurringIntentContext, RecurringIntentSpec,
};

pub(crate) const DEFAULT_WORK_LIMIT: usize = 4096;
const LOCAL_DERIVATION_WORK_MULTIPLIER: usize = 16;
const RUNTIME_TURN_PROFILE_ENV: &str = "TOPO_PROFILE_RUNTIME_TURNS";
const LEGACY_DAEMON_TURN_PROFILE_ENV: &str = "TOPO_PROFILE_DAEMON_TURNS";

/// Factory for the protocol's projector implementation.
pub type ProjectorFactory = fn() -> Box<dyn Projector>;
/// Protocol-owned declarations needed by core's runtime engine.
///
/// The description is static so a runtime instance cannot drift after opening
/// its database. `schema_sources` declare protocol tables, `row_mutation_tables`
/// is the allowlist for effects, `projector` defines projection, and `handlers`
/// define the queued work core may handle.
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
    /// Intent handlers this runtime may handle.
    pub handlers: &'static [HandlerRoute],
}

/// Protocol-owned declarations used by one runtime turn.
///
/// The same declaration is used by daemon-host turns and local command turns.
/// Host mode controls whether network adapters and durable handler dispatch are
/// available; the declaration only tells core how to classify inbound frames and
/// which time-wake timelines should be admitted.
#[derive(Clone, Copy)]
pub struct RuntimeTurnDescription {
    /// Classifier from inbound network bytes to protocol-owned incoming facts.
    pub inbound_network_intake: Option<InboundNetworkIntake>,
    /// Time-wake schedules runtime turns should admit.
    pub time_wakes: &'static [RuntimeTimeWake],
}

/// Function that turns an inbound frame into incoming projection inputs.
pub type InboundNetworkIntake = fn(InboundNetworkFrame) -> Result<Vec<Fact>, String>;

/// Opaque inbound TCP frame plus local receipt metadata.
#[derive(Debug, Clone)]
pub struct InboundNetworkFrame {
    pub frame: Vec<u8>,
    pub received_at_local_ms: u64,
}

/// One runtime-owned time wake declaration.
///
/// The protocol supplies both the timeline and the current high-water mark.
/// Core turns due rows in that interval into pending projection; projectors
/// decide whether the due time proves anything semantic.
#[derive(Clone, Copy)]
pub struct RuntimeTimeWake {
    /// Timeline namespace to process.
    pub timeline: fn() -> Timeline,
    /// Current inclusive high-water mark for that timeline.
    pub end_inclusive: fn(&Db) -> Result<Option<u64>, String>,
}

/// Host resources available to one bounded runtime turn.
///
/// The scheduler and queue order are the same for daemon and command/query
/// turns. A daemon turn supplies a listener, so network intake and outgoing TCP
/// pumping can run and durable handlers may dispatch. A command/query turn
/// supplies no listener; recurring local work, projection, local intents, and
/// time wakes still get a chance, while durable handler dispatch and network
/// host adapters are skipped.
#[derive(Clone, Copy)]
pub struct RuntimeTurnHost<'a> {
    listener: Option<&'a network::Listener>,
}

impl<'a> RuntimeTurnHost<'a> {
    pub fn daemon(listener: &'a network::Listener) -> Self {
        Self {
            listener: Some(listener),
        }
    }

    pub fn local() -> Self {
        Self { listener: None }
    }

    fn local_addr(self) -> Option<SocketAddr> {
        self.listener.map(network::Listener::local_addr)
    }

    fn runs_durable_handlers(self) -> bool {
        self.listener.is_some()
    }
}

/// In-memory set of protocol recurring operational intents.
///
/// Recurring intents are not durable state: each runtime host installs these
/// entries from the handler registry and gives them an opportunity during each
/// bounded runtime turn. Builders decide from database state, clock, and host
/// context whether to enqueue work. Nothing is persisted, so there is nothing
/// to wipe on rebuild and nothing to replay. The scheduler also skips a
/// recurring kind when local work for that kind is still queued, so operational
/// loops do not build an unbounded backlog.
pub struct RecurringScheduler {
    schedules: Vec<RecurringSchedule>,
}

struct RecurringSchedule {
    kind: &'static str,
    build_intent: RecurringIntentBuilder,
}

struct RecurringFire {
    queued: usize,
}

impl RecurringScheduler {
    /// Install in-memory recurring entries for every handler route with a recurrence.
    pub fn install(routes: &'static [HandlerRoute]) -> Self {
        let schedules = routes
            .iter()
            .filter_map(|route| {
                route.recurrence.map(|spec| RecurringSchedule {
                    kind: route.intent_kind,
                    build_intent: spec.build_intent,
                })
            })
            .collect();
        Self { schedules }
    }

    /// Number of installed recurring schedules.
    pub fn len(&self) -> usize {
        self.schedules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.schedules.is_empty()
    }

    fn offer(
        &mut self,
        runtime: &mut Runtime,
        now_ms: u64,
        local_addr: Option<SocketAddr>,
    ) -> Result<RecurringFire, String> {
        let mut fired = 0;
        for schedule in &mut self.schedules {
            if runtime.has_pending_local_intent_kind(schedule.kind)? {
                continue;
            }
            let builder_context = RecurringIntentContext { now_ms, local_addr };
            if let Some(intent) = (schedule.build_intent)(runtime.db(), builder_context)? {
                if intent.kind.as_str() != schedule.kind {
                    return Err(format!(
                        "recurring builder for {} produced intent kind {}",
                        schedule.kind,
                        intent.kind.as_str()
                    ));
                }
                runtime.submit_local_intent(intent)?;
                fired += 1;
            }
        }
        Ok(RecurringFire { queued: fired })
    }
}

/// Cross-process lock for one runtime turn against one database.
///
/// The daemon process and one-shot command processes both acquire this lock
/// before running a bounded runtime turn. The lock is separate from the daemon
/// lifecycle lock: it serializes queue/handler/projection work, not daemon
/// process ownership.
pub struct RuntimeTurnLock {
    file: File,
}

impl RuntimeTurnLock {
    pub fn acquire(db_path: &Path) -> Result<Self, String> {
        let path = runtime_turn_lock_path(db_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| format!("create runtime lock dir: {err}"))?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)
            .map_err(|err| format!("open runtime turn lock: {err}"))?;
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if rc != 0 {
            return Err(format!(
                "acquire runtime turn lock: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self { file })
    }
}

impl Drop for RuntimeTurnLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

/// Runtime for one concrete protocol description.
///
/// `Runtime` owns a single SQLite connection. All durable and memory tables,
/// projection, and intent handling happen through that handle so transaction
/// boundaries stay visible and ephemeral tables are actually local to this runtime
/// instance.
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

    pub(crate) fn has_pending_local_intent_kind(&self, kind: &str) -> Result<bool, String> {
        let pending: i64 = self
            .db
            .conn()
            .query_row(
                "SELECT EXISTS(
                    SELECT 1 FROM local_intents WHERE kind = ?1 LIMIT 1
                 )",
                rusqlite::params![kind],
                |row| row.get(0),
            )
            .map_err(|err| format!("check pending local intent kind {kind}: {err}"))?;
        Ok(pending != 0)
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

    /// Queue durable work for the protocol handler registry.
    ///
    /// The handler selected by `intent.kind` runs in a later runtime/daemon work
    /// pass. Use `submit_local_intent` for work that is only valid on this
    /// process and should disappear on restart.
    pub fn submit_intent(&mut self, intent: Intent) -> Result<(), String> {
        crate::core::handle_intent::validate_intent_kind_registered(
            &intent,
            self.handlers.intent_kinds(),
        )?;
        crate::core::handle_intent::submit_intent_to_queue(
            &self.db,
            crate::core::handle_intent::IntentQueue::Durable,
            intent,
        )
    }

    /// Queue ephemeral work for this runtime connection.
    pub fn submit_local_intent(&mut self, intent: Intent) -> Result<(), String> {
        crate::core::handle_intent::validate_intent_kind_registered(
            &intent,
            self.handlers.intent_kinds(),
        )?;
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
    /// This path is for live host work that is already volatile. It uses the
    /// same validation and atomic effect commit as projection and intent
    /// handling, but has no queued input row of its own to consume.
    pub(crate) fn submit_runtime_effects(
        &mut self,
        effects: RuntimeEffects,
        label: &str,
    ) -> Result<(), String> {
        project_fact::commit_effects::commit_runtime_effects_to_db(
            &self.db,
            &effects,
            self.description.row_mutation_tables,
            self.handlers.intent_kinds(),
            self.description.fact_admission,
            false,
            false,
            label,
        )
        .map(|_| ())
    }

    /// Stage protocol-classified network input for incoming projection.
    ///
    /// The facts remain volatile until their projectors choose to retain them.
    /// Core stores the receive metadata beside the incoming rows so projectors,
    /// not ingress code, decide whether it should become durable observation or
    /// receipt data.
    pub(crate) fn submit_network_incoming_facts(
        &mut self,
        facts: &[Fact],
        metadata: &IncomingMetadata,
        label: &str,
    ) -> Result<usize, String> {
        project_fact::commit_network_incoming_facts_to_db(
            &self.db,
            facts,
            metadata,
            self.description.fact_admission,
            label,
        )
    }

    // -------------------------------------------------------------------------
    // Bounded Queue Drains
    // -------------------------------------------------------------------------

    /// Drain at most `limit` durable projection items.
    ///
    /// Runtime owns the bounded loop; `project_fact` owns the one-item
    /// projection transaction. This keeps daemon scheduling visible without
    /// spreading projection commit details outside the projection worker.
    pub fn drain_durable_projection(&mut self, limit: usize) -> Result<bool, String> {
        self.drain_projection_source(ProjectionSource::Durable, limit)
    }

    /// Drain at most `limit` incoming projection items.
    ///
    /// Incoming facts are process-local intake. The daemon schedules this queue
    /// explicitly after durable projection so readers do not have to inspect
    /// `project_fact` to learn the live projection order.
    pub fn drain_incoming_projection(&mut self, limit: usize) -> Result<bool, String> {
        self.drain_projection_source(ProjectionSource::Incoming, limit)
    }

    fn drain_projection_source(
        &mut self,
        source: ProjectionSource,
        limit: usize,
    ) -> Result<bool, String> {
        drain_bounded_work(limit, || {
            project_fact::project_one(
                &self.db,
                self.projector.as_ref(),
                source,
                self.description.row_mutation_tables,
                self.handlers.intent_kinds(),
                self.description.fact_admission,
            )
        })
    }

    /// Drain at most `limit` durable intents using the live handler set.
    ///
    /// Runtime owns the bounded loop. `handle_intent` owns the one-row handler
    /// transaction.
    pub fn drain_durable_intents(&mut self, limit: usize) -> Result<bool, String> {
        self.drain_intent_queue(IntentQueue::Durable, limit)
    }

    /// Drain at most `limit` local intents using the live handler set.
    ///
    /// Only a successful handler-output commit consumes the row.
    pub fn drain_local_intents(&mut self, limit: usize) -> Result<bool, String> {
        self.drain_intent_queue(IntentQueue::Local, limit)
    }

    fn drain_intent_queue(&mut self, queue: IntentQueue, limit: usize) -> Result<bool, String> {
        drain_bounded_work(limit, || {
            handle_one_intent(
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
    // Runtime Turns
    // -------------------------------------------------------------------------

    /// Run one bounded runtime turn.
    ///
    /// Every host gives recurring builders an opportunity, then drains the queues
    /// in the same order. Missing host resources are no-ops: without a listener
    /// this turn does not dispatch durable handlers, accept new network bytes, or
    /// pump queued outgoing frames.
    pub fn run_turn(
        &mut self,
        description: RuntimeTurnDescription,
        host: RuntimeTurnHost<'_>,
        scheduler: &mut RecurringScheduler,
        work_limit: usize,
    ) -> Result<bool, String> {
        let mut active = false;
        let local_derivation_limit = local_derivation_work_limit(work_limit);
        let local_addr = host.local_addr();
        let runs_durable_handlers = host.runs_durable_handlers();
        let mut profile = RuntimeTurnProfile::start(local_addr);

        active |= profile.measure_bool("fire_recurring_intents", || {
            fire_recurring_intents(self, scheduler, local_addr)
        })?;
        active |= profile.measure_bool("drain_local_intents_pre", || {
            self.drain_local_intents(work_limit)
        })?;
        active |= profile.measure_bool("drain_durable_projection_pre", || {
            self.drain_durable_projection(local_derivation_limit)
        })?;

        active |= profile.measure_bool("drain_inbound_listener", || {
            drain_inbound_listener(description, self, host.listener, work_limit)
        })?;
        active |= profile.measure_bool("drain_inbound_network_queue", || {
            drain_inbound_network_queue(description, self, work_limit)
        })?;
        active |= profile.measure_bool("drain_time_wakes", || {
            drain_time_wakes(description, self, local_derivation_limit)
        })?;
        active |= profile.measure_bool("drain_durable_projection_post", || {
            self.drain_durable_projection(local_derivation_limit)
        })?;
        active |= profile.measure_bool("drain_incoming_projection", || {
            self.drain_incoming_projection(local_derivation_limit)
        })?;
        if runs_durable_handlers {
            active |= profile.measure_bool("drain_durable_intents", || {
                self.drain_durable_intents(work_limit)
            })?;
        }
        active |= profile.measure_bool("drain_local_intents_post", || {
            self.drain_local_intents(work_limit)
        })?;
        active |= profile.measure_bool("drain_outgoing_network", || {
            drain_outgoing_network(self, host.listener, work_limit)
        })?;
        profile.finish(active);
        Ok(active)
    }
}

fn local_derivation_work_limit(work_limit: usize) -> usize {
    work_limit
        .saturating_mul(LOCAL_DERIVATION_WORK_MULTIPLIER)
        .max(work_limit)
}

fn fire_recurring_intents(
    runtime: &mut Runtime,
    scheduler: &mut RecurringScheduler,
    local_addr: Option<SocketAddr>,
) -> Result<bool, String> {
    let offered = scheduler.offer(runtime, now_ms(), local_addr)?;
    Ok(offered.queued > 0)
}

fn drain_inbound_listener(
    description: RuntimeTurnDescription,
    runtime: &mut Runtime,
    listener: Option<&network::Listener>,
    work_limit: usize,
) -> Result<bool, String> {
    let Some(listener) = listener else {
        return Ok(false);
    };
    if description.inbound_network_intake.is_none() {
        return Ok(false);
    }
    let accepted = listener.accept_available(work_limit, |source, frame| {
        let row = network::IncomingNetworkRow::new(source, now_ms(), frame);
        network::enqueue_incoming(runtime.db(), std::slice::from_ref(&row)).map(|_| ())
    })?;
    Ok(accepted.accepted_connections > 0
        || accepted.value.sent_frames > 0
        || accepted.value.received_frames > 0)
}

fn drain_inbound_network_queue(
    description: RuntimeTurnDescription,
    runtime: &mut Runtime,
    work_limit: usize,
) -> Result<bool, String> {
    let Some(intake) = description.inbound_network_intake else {
        return Ok(false);
    };
    let rows = network::claim_incoming(runtime.db(), work_limit)?;
    for row in &rows {
        let facts = intake(InboundNetworkFrame {
            frame: row.bytes.clone(),
            received_at_local_ms: row.received_at_ms,
        })?;
        let metadata = IncomingMetadata {
            origin_addr: row.source.addr().to_string().into_bytes(),
            received_at_local_ms: row.received_at_ms,
        };
        runtime.submit_network_incoming_facts(
            &facts,
            &metadata,
            "stage inbound network incoming facts",
        )?;
        network::delete_incoming(runtime.db(), std::slice::from_ref(row))?;
    }
    Ok(!rows.is_empty())
}

fn drain_time_wakes(
    description: RuntimeTurnDescription,
    runtime: &mut Runtime,
    limit: usize,
) -> Result<bool, String> {
    let mut due = 0;
    let mut remaining = limit;
    for wake in description.time_wakes {
        if remaining == 0 {
            break;
        }
        let Some(end_inclusive) = (wake.end_inclusive)(runtime.db())? else {
            continue;
        };
        let admitted =
            runtime.process_due_time_range((wake.timeline)(), None, end_inclusive, remaining)?;
        due += admitted;
        remaining = remaining.saturating_sub(admitted);
    }
    Ok(due > 0)
}

fn drain_outgoing_network(
    runtime: &mut Runtime,
    listener: Option<&network::Listener>,
    work_limit: usize,
) -> Result<bool, String> {
    if listener.is_none() {
        return Ok(false);
    }
    let report = network::pump_outgoing(runtime.db(), work_limit, work_limit)?;
    Ok(report.sent_frames > 0)
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

struct RuntimeTurnProfile {
    enabled: bool,
    include_idle: bool,
    local_addr: Option<SocketAddr>,
    started: Instant,
    stages: Vec<RuntimeTurnStageProfile>,
}

struct RuntimeTurnStageProfile {
    name: &'static str,
    elapsed: Duration,
    result: bool,
}

impl RuntimeTurnProfile {
    fn start(local_addr: Option<SocketAddr>) -> Self {
        let (enabled, include_idle) = runtime_turn_profile_mode();
        Self {
            enabled,
            include_idle,
            local_addr,
            started: Instant::now(),
            stages: Vec::new(),
        }
    }

    #[cfg(test)]
    fn enabled_for_test(local_addr: Option<SocketAddr>, include_idle: bool) -> Self {
        Self {
            enabled: true,
            include_idle,
            local_addr,
            started: Instant::now(),
            stages: Vec::new(),
        }
    }

    fn measure_bool(
        &mut self,
        name: &'static str,
        work: impl FnOnce() -> Result<bool, String>,
    ) -> Result<bool, String> {
        if !self.enabled {
            return work();
        }
        let started = Instant::now();
        let result = work()?;
        self.stages.push(RuntimeTurnStageProfile {
            name,
            elapsed: started.elapsed(),
            result,
        });
        Ok(result)
    }

    fn finish(self, active: bool) {
        if let Some(line) = self.finish_line(active) {
            eprintln!("{line}");
        }
    }

    fn finish_line(self, active: bool) -> Option<String> {
        if !self.enabled || (!self.include_idle && !active) {
            return None;
        }
        let mut line = format!(
            "runtime_turn_profile addr={} active={} total_ms={}",
            self.local_addr
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "local".to_string()),
            active,
            duration_millis(self.started.elapsed())
        );
        for stage in self.stages {
            line.push_str(&format!(
                " {}_ms={} {}_result={}",
                stage.name,
                duration_millis(stage.elapsed),
                stage.name,
                usize::from(stage.result)
            ));
        }
        Some(line)
    }
}

fn runtime_turn_profile_mode() -> (bool, bool) {
    std::env::var(RUNTIME_TURN_PROFILE_ENV)
        .or_else(|_| std::env::var(LEGACY_DAEMON_TURN_PROFILE_ENV))
        .ok()
        .map(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            (
                !(normalized.is_empty() || normalized == "0" || normalized == "false"),
                normalized == "all",
            )
        })
        .unwrap_or((false, false))
}

fn duration_millis(duration: Duration) -> u128 {
    duration.as_micros() / 1000
}

pub(crate) fn runtime_turn_lock_path(db_path: &Path) -> PathBuf {
    derived_lock_path(db_path, ".runtime.lock", "runtime.lock")
}

fn derived_lock_path(db_path: &Path, suffix: &str, fallback: &str) -> PathBuf {
    let mut path = db_path.to_path_buf();
    let lock_name = db_path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{name}{suffix}"))
        .unwrap_or_else(|| fallback.to_string());
    path.set_file_name(lock_name);
    path
}

fn runtime_schema_sources(description: &RuntimeDescription) -> Vec<SchemaSource> {
    let mut sources = Vec::with_capacity(1 + description.schema_sources.len());
    sources.push(CORE_SCHEMA_SOURCE);
    sources.extend_from_slice(description.schema_sources);
    sources
}

fn drain_bounded_work(
    limit: usize,
    mut step: impl FnMut() -> Result<bool, String>,
) -> Result<bool, String> {
    let mut progressed = false;
    for _ in 0..limit {
        if !step()? {
            break;
        }
        progressed = true;
    }
    Ok(progressed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::effects::{RuntimeEffects, StorageRequirement};
    use crate::core::facts::{Fact, FactScope};
    use crate::core::intents::{HandlerContext, HandlerResult, IntentHandler, IntentKind};
    use crate::core::network::{NetworkTarget, OutgoingFrame};
    use crate::core::project_fact::{ProjectionContext, ProjectionOutput};
    use std::io::Read;
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

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
    static RECURRING_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);
    static FIRST_RECURRING_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);
    static SECOND_RECURRING_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);
    static DURABLE_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);

    const COUNTING_HANDLERS: &[HandlerRoute] = &[HandlerRoute {
        intent_kind: "counting",
        factory: counting_handler,
        storage_requirement: StorageRequirement::MaintenanceBypass,
        recurrence: None,
    }];

    const EMIT_FACT_HANDLERS: &[HandlerRoute] = &[HandlerRoute {
        intent_kind: "emit_fact",
        factory: emit_fact_handler,
        storage_requirement: StorageRequirement::MaintenanceBypass,
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

    const NETWORK_RUNTIME: RuntimeDescription = RuntimeDescription {
        schema_sources: &[network::SCHEMA_SOURCE],
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

    struct DurableHandler;

    impl IntentHandler for DurableHandler {
        fn handle(&self, intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
            assert_eq!(intent.kind.as_str(), "durable_work");
            DURABLE_HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(RuntimeEffects::new())
        }
    }

    fn durable_handler() -> Box<dyn IntentHandler> {
        Box::new(DurableHandler)
    }

    const DURABLE_HANDLERS: &[HandlerRoute] = &[HandlerRoute {
        intent_kind: "durable_work",
        factory: durable_handler,
        storage_requirement: StorageRequirement::MaintenanceBypass,
        recurrence: None,
    }];

    const DURABLE_RUNTIME: RuntimeDescription = RuntimeDescription {
        schema_sources: &[network::SCHEMA_SOURCE],
        row_mutation_tables: &[],
        projector: noop_projector,
        fact_routes: &[],
        fact_admission: None,
        handlers: DURABLE_HANDLERS,
    };

    struct RecurringHandler;

    impl IntentHandler for RecurringHandler {
        fn handle(&self, intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
            assert_eq!(intent.kind.as_str(), "recurring_tick");
            assert_eq!(intent.handler_key, b"cycle".to_vec());
            RECURRING_HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(RuntimeEffects::new())
        }
    }

    fn recurring_handler() -> Box<dyn IntentHandler> {
        Box::new(RecurringHandler)
    }

    fn recurring_builder(
        _store: &Db,
        context: RecurringIntentContext,
    ) -> Result<Option<Intent>, String> {
        assert!(
            context.local_addr.is_some(),
            "daemon-host runtime turn should pass its listen address to recurring builders"
        );
        Ok(Some(Intent::new(
            IntentKind::new("recurring_tick").expect("intent kind"),
            b"cycle".to_vec(),
            Vec::new(),
        )))
    }

    const RECURRING_HANDLERS: &[HandlerRoute] = &[HandlerRoute {
        intent_kind: "recurring_tick",
        factory: recurring_handler,
        storage_requirement: StorageRequirement::MaintenanceBypass,
        recurrence: Some(RecurringIntentSpec {
            build_intent: recurring_builder,
        }),
    }];

    const RECURRING_RUNTIME: RuntimeDescription = RuntimeDescription {
        schema_sources: &[network::SCHEMA_SOURCE],
        row_mutation_tables: &[],
        projector: noop_projector,
        fact_routes: &[],
        fact_admission: None,
        handlers: RECURRING_HANDLERS,
    };

    struct FirstRecurringHandler;

    impl IntentHandler for FirstRecurringHandler {
        fn handle(&self, intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
            assert_eq!(intent.kind.as_str(), "first_recurring");
            FIRST_RECURRING_HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(RuntimeEffects::new())
        }
    }

    fn first_recurring_handler() -> Box<dyn IntentHandler> {
        Box::new(FirstRecurringHandler)
    }

    fn first_recurring_builder(
        _store: &Db,
        _context: RecurringIntentContext,
    ) -> Result<Option<Intent>, String> {
        Ok(Some(Intent::new(
            IntentKind::new("first_recurring").expect("intent kind"),
            b"first".to_vec(),
            Vec::new(),
        )))
    }

    struct SecondRecurringHandler;

    impl IntentHandler for SecondRecurringHandler {
        fn handle(&self, intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
            assert_eq!(intent.kind.as_str(), "second_recurring");
            SECOND_RECURRING_HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(RuntimeEffects::new())
        }
    }

    fn second_recurring_handler() -> Box<dyn IntentHandler> {
        Box::new(SecondRecurringHandler)
    }

    fn second_recurring_builder(
        _store: &Db,
        _context: RecurringIntentContext,
    ) -> Result<Option<Intent>, String> {
        Ok(Some(Intent::new(
            IntentKind::new("second_recurring").expect("intent kind"),
            b"second".to_vec(),
            Vec::new(),
        )))
    }

    const MULTI_RECURRING_HANDLERS: &[HandlerRoute] = &[
        HandlerRoute {
            intent_kind: "first_recurring",
            factory: first_recurring_handler,
            storage_requirement: StorageRequirement::MaintenanceBypass,
            recurrence: Some(RecurringIntentSpec {
                build_intent: first_recurring_builder,
            }),
        },
        HandlerRoute {
            intent_kind: "second_recurring",
            factory: second_recurring_handler,
            storage_requirement: StorageRequirement::MaintenanceBypass,
            recurrence: Some(RecurringIntentSpec {
                build_intent: second_recurring_builder,
            }),
        },
    ];

    const MULTI_RECURRING_RUNTIME: RuntimeDescription = RuntimeDescription {
        schema_sources: &[network::SCHEMA_SOURCE],
        row_mutation_tables: &[],
        projector: noop_projector,
        fact_routes: &[],
        fact_admission: None,
        handlers: MULTI_RECURRING_HANDLERS,
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
            "one intent batch should handle at most its limit"
        );
        assert_eq!(intent_runtime.pending_intent_count(), 1);
    }

    #[test]
    fn runtime_rejects_intents_without_registered_handlers() {
        let mut runtime = Runtime::open_memory(&HANDLER_RUNTIME).expect("runtime");
        let durable = runtime
            .submit_intent(Intent::new(
                IntentKind::new("missing").expect("intent kind"),
                b"one".to_vec(),
                Vec::new(),
            ))
            .expect_err("unknown durable intent should reject");
        let local = runtime
            .submit_local_intent(Intent::new(
                IntentKind::new("missing").expect("intent kind"),
                b"two".to_vec(),
                Vec::new(),
            ))
            .expect_err("unknown local intent should reject");

        assert!(
            durable.contains("intent kind missing is not registered"),
            "{durable}"
        );
        assert!(
            local.contains("intent kind missing is not registered"),
            "{local}"
        );
        assert_eq!(runtime.pending_intent_count(), 0);
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

        assert!(first);
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

        assert!(second);
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
    fn runtime_turn_profile_formats_recorded_stage_timings() {
        let local_addr = "127.0.0.1:4242".parse().expect("addr");
        let mut profile = RuntimeTurnProfile::enabled_for_test(Some(local_addr), false);

        let result = profile
            .measure_bool("stage", || Ok(true))
            .expect("stage result");

        assert!(result);
        let line = profile.finish_line(true).expect("profile line");
        assert!(line.contains("runtime_turn_profile addr=127.0.0.1:4242 active=true"));
        assert!(line.contains("stage_ms="));
        assert!(line.contains("stage_result=1"));
    }

    #[test]
    fn runtime_turn_pumps_queued_outgoing_rows_after_runtime_work() {
        let peer = TcpListener::bind("127.0.0.1:0").expect("bind outgoing peer");
        let peer_addr = peer.local_addr().expect("peer addr");
        let reader = thread::spawn(move || {
            let (mut stream, _) = peer.accept().expect("accept outgoing pump");
            read_length_prefixed_frame(&mut stream)
        });
        let listener =
            network::listen("127.0.0.1:0".parse().expect("listen addr")).expect("daemon listener");
        let mut runtime = Runtime::open_memory(&NETWORK_RUNTIME).expect("runtime");
        network::queue_outgoing(
            runtime.db(),
            NetworkTarget::new(peer_addr),
            OutgoingFrame {
                bytes: b"tick queued frame".to_vec(),
            },
        )
        .expect("queue outgoing frame");
        let mut scheduler = RecurringScheduler::install(NETWORK_RUNTIME.handlers);

        let active = runtime
            .run_turn(
                RuntimeTurnDescription {
                    inbound_network_intake: None,
                    time_wakes: &[],
                },
                RuntimeTurnHost::daemon(&listener),
                &mut scheduler,
                16,
            )
            .expect("daemon runtime turn");

        assert!(active);
        assert_eq!(reader.join().expect("reader thread"), b"tick queued frame");
        assert!(network::claim_outgoing_for_target(
            runtime.db(),
            NetworkTarget::new(peer_addr),
            16
        )
        .expect("claim after tick")
        .is_empty());
    }

    #[test]
    fn runtime_turn_uses_high_local_derivation_budget_for_projection() {
        let listener =
            network::listen("127.0.0.1:0".parse().expect("listen addr")).expect("daemon listener");
        let mut runtime = Runtime::open_memory(&NETWORK_RUNTIME).expect("runtime");
        let mut scheduler = RecurringScheduler::install(NETWORK_RUNTIME.handlers);
        runtime.submit_fact(Fact::new(FactScope::Global, 7, b"one".to_vec()));
        runtime.submit_fact(Fact::new(FactScope::Global, 7, b"two".to_vec()));

        runtime
            .run_turn(
                RuntimeTurnDescription {
                    inbound_network_intake: None,
                    time_wakes: &[],
                },
                RuntimeTurnHost::daemon(&listener),
                &mut scheduler,
                1,
            )
            .expect("daemon runtime turn");

        assert_eq!(
            runtime.pending_projection_count(),
            0,
            "projection should use the high local-derivation budget, not the base side-effect limit"
        );
    }

    #[test]
    fn local_runtime_turn_leaves_durable_intents_for_daemon_host() {
        DURABLE_HANDLER_CALLS.store(0, Ordering::SeqCst);
        let listener =
            network::listen("127.0.0.1:0".parse().expect("listen addr")).expect("daemon listener");
        let mut runtime = Runtime::open_memory(&DURABLE_RUNTIME).expect("runtime");
        runtime
            .submit_intent(Intent::new(
                IntentKind::new("durable_work").expect("intent kind"),
                b"durable".to_vec(),
                Vec::new(),
            ))
            .expect("submit durable intent");
        let mut scheduler = RecurringScheduler::install(DURABLE_RUNTIME.handlers);

        let local_active = runtime
            .run_turn(
                RuntimeTurnDescription {
                    inbound_network_intake: None,
                    time_wakes: &[],
                },
                RuntimeTurnHost::local(),
                &mut scheduler,
                16,
            )
            .expect("local runtime turn");

        assert!(!local_active);
        assert_eq!(DURABLE_HANDLER_CALLS.load(Ordering::SeqCst), 0);
        assert_eq!(
            runtime.pending_intent_count(),
            1,
            "local command/query turns must not consume daemon-host durable work"
        );

        let daemon_active = runtime
            .run_turn(
                RuntimeTurnDescription {
                    inbound_network_intake: None,
                    time_wakes: &[],
                },
                RuntimeTurnHost::daemon(&listener),
                &mut scheduler,
                16,
            )
            .expect("daemon runtime turn");

        assert!(daemon_active);
        assert_eq!(DURABLE_HANDLER_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(runtime.pending_intent_count(), 0);
    }

    #[test]
    fn runtime_turn_fires_recurring_intents_before_drain_steps() {
        RECURRING_HANDLER_CALLS.store(0, Ordering::SeqCst);
        let listener =
            network::listen("127.0.0.1:0".parse().expect("listen addr")).expect("daemon listener");
        let mut runtime = Runtime::open_memory(&RECURRING_RUNTIME).expect("runtime");
        let mut scheduler = RecurringScheduler::install(RECURRING_RUNTIME.handlers);

        let active = runtime
            .run_turn(
                RuntimeTurnDescription {
                    inbound_network_intake: None,
                    time_wakes: &[],
                },
                RuntimeTurnHost::daemon(&listener),
                &mut scheduler,
                16,
            )
            .expect("daemon runtime turn");

        assert!(active);
        assert_eq!(RECURRING_HANDLER_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(
            runtime.pending_intent_count(),
            0,
            "the same runtime turn should dispatch the recurring intent it offered"
        );
    }

    #[test]
    fn runtime_turn_does_not_duplicate_pending_recurring_local_work() {
        RECURRING_HANDLER_CALLS.store(0, Ordering::SeqCst);
        let listener =
            network::listen("127.0.0.1:0".parse().expect("listen addr")).expect("daemon listener");
        let mut runtime = Runtime::open_memory(&RECURRING_RUNTIME).expect("runtime");
        let mut scheduler = RecurringScheduler::install(RECURRING_RUNTIME.handlers);
        runtime
            .submit_local_intent(Intent::new(
                IntentKind::new("recurring_tick").expect("intent kind"),
                b"cycle".to_vec(),
                Vec::new(),
            ))
            .expect("queue existing local recurring work");
        assert_eq!(runtime.pending_intent_count(), 1);

        let active = runtime
            .run_turn(
                RuntimeTurnDescription {
                    inbound_network_intake: None,
                    time_wakes: &[],
                },
                RuntimeTurnHost::daemon(&listener),
                &mut scheduler,
                16,
            )
            .expect("daemon runtime turn");

        assert!(active);
        assert_eq!(
            RECURRING_HANDLER_CALLS.load(Ordering::SeqCst),
            1,
            "pending recurring work should block the builder from queuing a duplicate"
        );
        assert_eq!(runtime.pending_intent_count(), 0);
    }

    #[test]
    fn runtime_turn_fires_all_recurring_intents_through_normal_path() {
        FIRST_RECURRING_HANDLER_CALLS.store(0, Ordering::SeqCst);
        SECOND_RECURRING_HANDLER_CALLS.store(0, Ordering::SeqCst);
        let listener =
            network::listen("127.0.0.1:0".parse().expect("listen addr")).expect("daemon listener");
        let mut runtime = Runtime::open_memory(&MULTI_RECURRING_RUNTIME).expect("runtime");
        let mut scheduler = RecurringScheduler::install(MULTI_RECURRING_RUNTIME.handlers);

        let status = runtime
            .run_turn(
                RuntimeTurnDescription {
                    inbound_network_intake: None,
                    time_wakes: &[],
                },
                RuntimeTurnHost::daemon(&listener),
                &mut scheduler,
                16,
            )
            .expect("daemon runtime turn");

        assert!(status);
        assert_eq!(FIRST_RECURRING_HANDLER_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(
            SECOND_RECURRING_HANDLER_CALLS.load(Ordering::SeqCst),
            1,
            "recurring handlers should share the same normal scheduling path"
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

    fn read_length_prefixed_frame(stream: &mut TcpStream) -> Vec<u8> {
        let mut len = [0u8; 4];
        stream.read_exact(&mut len).expect("read frame length");
        let mut body = vec![0; u32::from_be_bytes(len) as usize];
        stream.read_exact(&mut body).expect("read frame body");
        body
    }
}
