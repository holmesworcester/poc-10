//! Process lifecycle for a long-running protocol `start` command.
//!
//! Core owns only the reusable mechanics: parse daemon flags, hold the
//! per-database lock, bind the TCP listener, publish the readiness line, react to
//! stop/reset, and run a bounded turn from the selected protocol's declarative
//! daemon description. The turn is protocol-agnostic: give recurring builders a
//! chance to repair storage readiness, block host IO until any declared
//! readiness check passes, then optionally accept network bytes, stage and drain
//! protocol-classified incoming facts, process declared time wakes with a high
//! local budget, drain projection and intents, and optionally pump queued
//! outgoing network bytes.
//!
//! The daemon is the host that supplies network adapters for the shared runtime
//! turn. It does not decode connection frames or choose protocol actions itself.
//! The protocol declaration classifies inbound bytes as incoming facts, declares
//! which time-wake timelines should be admitted, and supplies the runtime
//! handlers that consume queued work.
//!
//! The order inside `runtime_turn` is part of the runtime contract. The first
//! recurring intent that queues work runs before other recurring entries and
//! before host IO. If the protocol readiness check is still false, only queued
//! repair/rebuild work drains. Once ready, recurring work runs before inbound
//! network input, due time ranges wake facts, projection and intents drain, and
//! queued outgoing TCP bytes are pumped by target address when the host supplied
//! a listener.
//! Handler-emitted facts remain queued for later projection work. Change that
//! order here only if the whole runtime turn scheduling policy changes; protocol
//! handlers should adapt by emitting facts, time wakes, or intents rather than
//! calling turn steps directly.

use crate::core::cli::{CliArgs, CliOutput};
use crate::core::db::Db;
use crate::core::facts::Fact;
use crate::core::handle_intent::{HandlerRoute, RecurringIntentBuilder, RecurringIntentContext};
use crate::core::network;
use crate::core::project_fact::{IncomingMetadata, Timeline};
use crate::core::runtime::Runtime;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const START_USAGE: &str = "start --listen IP PORT [--tick-ms N] [--quiet-ms N]";
const STOP_USAGE: &str = "stop";
const RESET_USAGE: &str = "reset";
const DEFAULT_TICK_MS: u64 = 250;
pub(crate) const DEFAULT_WORK_LIMIT: usize = 4096;
const LOCAL_DERIVATION_WORK_MULTIPLIER: usize = 16;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const DAEMON_TURN_PROFILE_ENV: &str = "TOPO_PROFILE_DAEMON_TURNS";

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_termination_signal(_signal: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

/// Parsed daemon start options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartOptions {
    /// Address the daemon should bind.
    pub listen: SocketAddr,
    /// Sleep duration after an idle daemon turn.
    pub quiet_ms: u64,
    /// Base maximum queued items one tick should process per side-effecting stage.
    /// Local derivation queues use a larger derived budget.
    pub work_limit: usize,
}

/// Protocol declarations needed by daemon-host runtime turns.
#[derive(Clone, Copy)]
pub struct DaemonDescription {
    /// Classifier from inbound network bytes to protocol-owned incoming facts.
    pub inbound_network_intake: Option<InboundNetworkIntake>,
    /// Time-wake schedules daemon-host runtime turns should admit.
    pub time_wakes: &'static [DaemonTimeWake],
    /// Optional protocol-owned guard for derived-state readiness.
    pub storage_ready: Option<StorageReadyCheck>,
}

/// Function that turns an inbound frame into incoming projection inputs.
pub type InboundNetworkIntake = fn(InboundNetworkFrame) -> Result<Vec<Fact>, String>;

/// Protocol-owned check that decides whether normal daemon work may run.
pub type StorageReadyCheck = fn(&Db) -> Result<bool, String>;

/// Opaque inbound TCP frame plus local receipt metadata.
#[derive(Debug, Clone)]
pub struct InboundNetworkFrame {
    pub frame: Vec<u8>,
    pub received_at_local_ms: u64,
}

/// One daemon-owned time wake declaration.
///
/// The protocol supplies both the timeline and the current high-water mark.
/// Core turns due rows in that interval into pending projection.
#[derive(Clone, Copy)]
pub struct DaemonTimeWake {
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
/// supplies no listener; recurring local repair work, projection, local
/// intents, and time wakes still get a chance, while durable handler dispatch
/// and network host adapters are skipped.
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

/// Run one bounded runtime turn.
///
/// Every host gives recurring builders an opportunity, then drains the queues in
/// the same order. Missing host resources are no-ops: without a listener this
/// turn does not dispatch durable handlers, accept new network bytes, or pump
/// queued outgoing frames.
pub fn runtime_turn(
    description: DaemonDescription,
    runtime: &mut Runtime,
    host: RuntimeTurnHost<'_>,
    scheduler: &mut RecurringScheduler,
    work_limit: usize,
) -> Result<bool, String> {
    let mut active = false;
    let local_derivation_limit = local_derivation_work_limit(work_limit);
    let local_addr = host.local_addr();
    let runs_durable_handlers = host.runs_durable_handlers();
    let mut recurring_resume_at = 0;
    let mut profile = DaemonTurnProfile::start(local_addr);

    if !profile.measure_bool("readiness_gate", || {
        run_readiness_gate(
            description,
            runtime,
            local_addr,
            runs_durable_handlers,
            scheduler,
            work_limit,
            local_derivation_limit,
            &mut active,
            &mut recurring_resume_at,
        )
    })? {
        profile.finish(active);
        return Ok(active);
    }

    active |= profile.measure_bool("fire_recurring_intents", || {
        fire_recurring_intents(runtime, scheduler, local_addr, recurring_resume_at)
    })?;
    active |= profile.measure_bool("drain_local_intents_pre", || {
        runtime.drain_local_intents(work_limit)
    })?;
    active |= profile.measure_bool("drain_durable_projection_pre", || {
        runtime.drain_durable_projection(local_derivation_limit)
    })?;
    if !profile.measure_bool("storage_ready_or_drain_repair", || {
        storage_ready_or_drain_repair(
            description,
            runtime,
            runs_durable_handlers,
            work_limit,
            local_derivation_limit,
            &mut active,
        )
    })? {
        profile.finish(active);
        return Ok(active);
    }

    active |= profile.measure_bool("drain_inbound_listener", || {
        drain_inbound_listener(description, runtime, host.listener, work_limit)
    })?;
    active |= profile.measure_bool("drain_inbound_network_queue", || {
        drain_inbound_network_queue(description, runtime, work_limit)
    })?;
    active |= profile.measure_bool("drain_time_wakes", || {
        drain_time_wakes(description, runtime, local_derivation_limit)
    })?;
    active |= profile.measure_bool("drain_durable_projection_post", || {
        runtime.drain_durable_projection(local_derivation_limit)
    })?;
    active |= profile.measure_bool("drain_incoming_projection", || {
        runtime.drain_incoming_projection(local_derivation_limit)
    })?;
    if runs_durable_handlers {
        active |= profile.measure_bool("drain_durable_intents", || {
            runtime.drain_durable_intents(work_limit)
        })?;
    }
    active |= profile.measure_bool("drain_local_intents_post", || {
        runtime.drain_local_intents(work_limit)
    })?;
    active |= profile.measure_bool("drain_outgoing_network", || {
        drain_outgoing_network(runtime, host.listener, work_limit)
    })?;
    profile.finish(active);
    Ok(active)
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
    start_index: usize,
) -> Result<bool, String> {
    let offered = scheduler.offer(runtime, now_ms(), local_addr, start_index, false)?;
    Ok(offered.queued > 0)
}

fn fire_first_recurring_intent(
    runtime: &mut Runtime,
    scheduler: &mut RecurringScheduler,
    local_addr: Option<SocketAddr>,
) -> Result<RecurringFire, String> {
    scheduler.offer(runtime, now_ms(), local_addr, 0, true)
}

fn run_readiness_gate(
    description: DaemonDescription,
    runtime: &mut Runtime,
    local_addr: Option<SocketAddr>,
    runs_durable_handlers: bool,
    scheduler: &mut RecurringScheduler,
    work_limit: usize,
    local_derivation_limit: usize,
    active: &mut bool,
    recurring_resume_at: &mut usize,
) -> Result<bool, String> {
    let first_recurring = fire_first_recurring_intent(runtime, scheduler, local_addr)?;
    *recurring_resume_at = first_recurring.resume_at;
    *active |= first_recurring.queued > 0;
    if first_recurring.queued > 0 {
        *active |= runtime.drain_local_intents(1)?;
        *active |= runtime.drain_durable_projection(local_derivation_limit)?;
    }
    storage_ready_or_drain_repair(
        description,
        runtime,
        runs_durable_handlers,
        work_limit,
        local_derivation_limit,
        active,
    )
}

fn storage_ready_or_drain_repair(
    description: DaemonDescription,
    runtime: &mut Runtime,
    runs_durable_handlers: bool,
    work_limit: usize,
    local_derivation_limit: usize,
    active: &mut bool,
) -> Result<bool, String> {
    if storage_ready(description, runtime)? {
        return Ok(true);
    }
    *active |= drain_repair_work(
        runtime,
        local_derivation_limit,
        work_limit,
        runs_durable_handlers,
    )?;
    Ok(false)
}

fn storage_ready(description: DaemonDescription, runtime: &Runtime) -> Result<bool, String> {
    let Some(check) = description.storage_ready else {
        return Ok(true);
    };
    check(runtime.db())
}

fn drain_repair_work(
    runtime: &mut Runtime,
    local_derivation_limit: usize,
    work_limit: usize,
    runs_durable_handlers: bool,
) -> Result<bool, String> {
    let mut active = false;
    active |= runtime.drain_durable_projection(local_derivation_limit)?;
    active |= runtime.drain_incoming_projection(local_derivation_limit)?;
    if runs_durable_handlers {
        active |= runtime.drain_durable_intents(work_limit)?;
    }
    active |= runtime.drain_local_intents(work_limit)?;
    Ok(active)
}

fn drain_inbound_listener(
    description: DaemonDescription,
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
    description: DaemonDescription,
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
    description: DaemonDescription,
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

struct DaemonTurnProfile {
    enabled: bool,
    include_idle: bool,
    local_addr: Option<SocketAddr>,
    started: Instant,
    stages: Vec<DaemonTurnStageProfile>,
}

struct DaemonTurnStageProfile {
    name: &'static str,
    elapsed: Duration,
    result: bool,
}

impl DaemonTurnProfile {
    fn start(local_addr: Option<SocketAddr>) -> Self {
        let (enabled, include_idle) = daemon_turn_profile_mode();
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
        self.stages.push(DaemonTurnStageProfile {
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
            "daemon_turn_profile addr={} active={} total_ms={}",
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

fn daemon_turn_profile_mode() -> (bool, bool) {
    std::env::var(DAEMON_TURN_PROFILE_ENV)
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

/// In-memory set of protocol recurring operational intents.
///
/// Recurring intents are not durable state: each runtime host installs these
/// entries from the handler registry and gives them an opportunity during each
/// bounded runtime turn. Builders decide from database state, clock, and host
/// context whether to enqueue work. Nothing is persisted, so there is nothing
/// to wipe on rebuild and nothing to replay. A protocol can put a
/// storage-readiness check first in the registry; `runtime_turn` gives that
/// first recurring entry a chance to queue and drain repair work before later
/// recurring entries run. The scheduler also skips a recurring kind when local
/// work for that kind is still queued, so operational loops do not build an
/// unbounded backlog.
pub struct RecurringScheduler {
    schedules: Vec<RecurringSchedule>,
}

struct RecurringSchedule {
    kind: &'static str,
    build_intent: RecurringIntentBuilder,
}

struct RecurringFire {
    queued: usize,
    resume_at: usize,
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
        start_index: usize,
        stop_after_queue: bool,
    ) -> Result<RecurringFire, String> {
        let mut fired = 0;
        let mut resume_at = self.schedules.len();
        for (index, schedule) in self.schedules.iter_mut().enumerate().skip(start_index) {
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
            if stop_after_queue && fired > 0 {
                resume_at = index.saturating_add(1);
                break;
            }
        }
        Ok(RecurringFire {
            queued: fired,
            resume_at,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DaemonReport {
    /// Bound listener address, including the assigned port for `:0`.
    pub local_addr: Option<SocketAddr>,
    /// Number of loop ticks completed before shutdown.
    pub ticks: usize,
}

impl DaemonReport {
    fn lines(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(local_addr) = self.local_addr {
            out.push(format!("listening: {local_addr}"));
        }
        out.push(format!("ticks: {}", self.ticks));
        out
    }
}

/// Run the long-lived daemon loop until SIGINT/SIGTERM or `stop`.
pub fn start(
    db_path: &Path,
    args: CliArgs<'_>,
    mut run_turn: impl FnMut(&network::Listener, usize) -> Result<bool, String>,
) -> Result<CliOutput, String> {
    let options = parse_start_options(args)?;
    SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
    install_termination_handlers();

    let lock = DaemonLock::acquire(db_path)?;
    let listener = network::listen(options.listen)?;
    let local_addr = listener.local_addr();
    lock.record_listen_addr(local_addr)?;
    print_line_now(&format!("listening: {local_addr}"))?;

    let mut report = DaemonReport {
        local_addr: Some(local_addr),
        ..DaemonReport::default()
    };
    while !SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
        let turn_activity = {
            let _turn = RuntimeTurnLock::acquire(db_path)?;
            run_turn(&listener, options.work_limit)?
        };
        let sleep_after_tick = sleep_after_tick(&options, turn_activity);
        report.ticks += 1;
        std::thread::yield_now();
        if let Some(duration) = sleep_after_tick {
            std::thread::sleep(duration);
        }
    }

    Ok(CliOutput::lines(report.lines()))
}

/// Ask the daemon for this database to stop, using its sibling lock file.
pub fn stop(db_path: &Path, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(0, STOP_USAGE)?;
    Ok(CliOutput::lines(stop_daemon(db_path)?))
}

/// Stop the daemon if needed and remove the database, WAL, SHM, and lock files.
pub fn reset(db_path: &Path, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(0, RESET_USAGE)?;
    let mut lines = stop_daemon(db_path)?;
    lines.extend(reset_db_files(db_path)?);
    Ok(CliOutput::lines(lines))
}

/// Read the current daemon listen address from the sibling lock file.
pub fn current_listen_addr(db_path: &Path) -> Result<Option<SocketAddr>, String> {
    let text = match fs::read_to_string(lock_path(db_path)) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(format!("read daemon lock: {err}")),
    };
    let mut lines = text.lines();
    let Some(pid_line) = lines.next() else {
        return Ok(None);
    };
    let Ok(pid) = pid_line.trim().parse::<u32>() else {
        return Ok(None);
    };
    if !process_exists(pid) {
        return Ok(None);
    }
    let Some(addr_line) = lines.next() else {
        return Ok(None);
    };
    addr_line
        .trim()
        .parse::<SocketAddr>()
        .map(Some)
        .map_err(|err| format!("daemon lock listen addr is invalid: {err}"))
}

fn parse_start_options(args: CliArgs<'_>) -> Result<StartOptions, String> {
    let mut listen = None;
    let mut tick_ms = DEFAULT_TICK_MS;
    let mut quiet_ms = None;
    let mut idx = 0;
    while idx < args.values().len() {
        match args.get(idx).expect("index in bounds") {
            "--listen" => {
                let ip = args.get(idx + 1).ok_or_else(|| START_USAGE.to_string())?;
                let port = args.get(idx + 2).ok_or_else(|| START_USAGE.to_string())?;
                listen = Some(
                    format!("{ip}:{port}")
                        .parse::<SocketAddr>()
                        .map_err(|_| START_USAGE.to_string())?,
                );
                idx += 3;
            }
            "--sync-ms" | "--tick-ms" => {
                tick_ms = parse_positive_u64(args.get(idx + 1))?;
                idx += 2;
            }
            "--quiet-ms" => {
                quiet_ms = Some(parse_positive_u64(args.get(idx + 1))?);
                idx += 2;
            }
            other => return Err(format!("unknown start option `{other}`\n{START_USAGE}")),
        }
    }
    Ok(StartOptions {
        listen: listen.ok_or_else(|| START_USAGE.to_string())?,
        quiet_ms: quiet_ms.unwrap_or(tick_ms),
        work_limit: DEFAULT_WORK_LIMIT,
    })
}

fn sleep_after_tick(options: &StartOptions, active: bool) -> Option<Duration> {
    (!active).then(|| Duration::from_millis(options.quiet_ms))
}

fn parse_positive_u64(value: Option<&str>) -> Result<u64, String> {
    let parsed = value
        .ok_or_else(|| START_USAGE.to_string())?
        .parse::<u64>()
        .map_err(|_| START_USAGE.to_string())?;
    if parsed == 0 {
        return Err(START_USAGE.to_string());
    }
    Ok(parsed)
}

fn install_termination_handlers() {
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if INSTALLED.swap(true, Ordering::SeqCst) {
        return;
    }
    let handler = handle_termination_signal as *const () as libc::sighandler_t;
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = handler;
        action.sa_flags = libc::SA_RESTART;
        libc::sigemptyset(&mut action.sa_mask);
        libc::sigaction(libc::SIGTERM, &action, std::ptr::null_mut());
        libc::sigaction(libc::SIGINT, &action, std::ptr::null_mut());
    }
}

fn stop_daemon(db_path: &Path) -> Result<Vec<String>, String> {
    let lock = lock_path(db_path);
    let pid = match read_lock_pid(&lock)? {
        LockState::Missing => return Ok(vec!["no daemon running".to_string()]),
        LockState::Unreadable => {
            let _ = fs::remove_file(&lock);
            return Ok(vec![
                "no daemon running (cleared unreadable lock)".to_string()
            ]);
        }
        LockState::Pid(pid) => pid,
    };

    if !process_exists(pid) {
        let _ = fs::remove_file(&lock);
        return Ok(vec![format!(
            "no daemon running (cleared stale lock for pid {pid})"
        )]);
    }

    send_termination_signal(pid)?;
    let deadline = Instant::now() + SHUTDOWN_TIMEOUT;
    while Instant::now() < deadline {
        if !lock.exists() {
            return Ok(vec![format!("stopped daemon (pid {pid})")]);
        }
        if !process_exists(pid) {
            let _ = fs::remove_file(&lock);
            return Ok(vec![format!(
                "daemon process exited (pid {pid}); cleared remaining lock"
            )]);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(format!(
        "daemon (pid {pid}) did not exit within {}s",
        SHUTDOWN_TIMEOUT.as_secs()
    ))
}

fn reset_db_files(db_path: &Path) -> Result<Vec<String>, String> {
    let db_path = validate_reset_path(db_path)?;
    let candidates = [
        db_path.clone(),
        sibling_path(&db_path, "-wal"),
        sibling_path(&db_path, "-shm"),
        lock_path(&db_path),
        runtime_turn_lock_path(&db_path),
    ];
    let mut deleted = Vec::new();
    for candidate in &candidates {
        match fs::remove_file(candidate) {
            Ok(()) => deleted.push(format!("deleted: {}", candidate.display())),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(format!("delete {}: {err}", candidate.display())),
        }
    }
    if deleted.is_empty() {
        deleted.push("nothing to reset".to_string());
    } else {
        deleted.push("reset complete".to_string());
    }
    Ok(deleted)
}

fn validate_reset_path(db_path: &Path) -> Result<PathBuf, String> {
    if db_path.as_os_str().is_empty() {
        return Err("reset: empty db path".to_string());
    }
    let parent = db_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .ok_or_else(|| {
            format!(
                "reset: refusing to operate on db path with no parent directory ({})",
                db_path.display()
            )
        })?;
    if db_path
        .file_name()
        .and_then(|name| name.to_str())
        .is_none_or(|name| name.is_empty() || name == "." || name == "..")
    {
        return Err(format!(
            "reset: refusing to operate on db path without a file name ({})",
            db_path.display()
        ));
    }
    let parent_abs = parent
        .canonicalize()
        .unwrap_or_else(|_| parent.to_path_buf());
    if parent_abs.as_os_str().is_empty() || parent_abs == Path::new("/") {
        return Err(format!(
            "reset: refusing to operate inside `{}`",
            parent_abs.display()
        ));
    }
    Ok(db_path.to_path_buf())
}

fn sibling_path(db_path: &Path, suffix: &str) -> PathBuf {
    let mut sibling = db_path.as_os_str().to_owned();
    sibling.push(suffix);
    PathBuf::from(sibling)
}

enum LockState {
    Missing,
    Unreadable,
    Pid(u32),
}

fn read_lock_pid(lock: &Path) -> Result<LockState, String> {
    match fs::read_to_string(lock) {
        Ok(text) => {
            let pid_line = text.lines().next().unwrap_or("");
            match pid_line.trim().parse::<u32>() {
                Ok(pid) if pid > 0 => Ok(LockState::Pid(pid)),
                _ => Ok(LockState::Unreadable),
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(LockState::Missing),
        Err(err) => Err(format!("read daemon lock: {err}")),
    }
}

fn process_exists(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

fn send_termination_signal(pid: u32) -> Result<(), String> {
    let result = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if result == 0 {
        Ok(())
    } else {
        let errno = std::io::Error::last_os_error();
        if errno.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(format!("send SIGTERM to {pid}: {errno}"))
        }
    }
}

struct DaemonLock {
    path: PathBuf,
    _file: File,
}

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

impl DaemonLock {
    fn acquire(db_path: &Path) -> Result<Self, String> {
        let path = lock_path(db_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| format!("create lock dir: {err}"))?;
        }
        match create_lock_file(&path) {
            Ok(file) => Ok(Self { path, _file: file }),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                if stale_lock_can_be_removed(&path)? {
                    let _ = fs::remove_file(&path);
                    let file = create_lock_file(&path)
                        .map_err(|err| format!("create daemon lock: {err}"))?;
                    Ok(Self { path, _file: file })
                } else {
                    Err(format!(
                        "daemon already running for {}",
                        db_path.to_string_lossy()
                    ))
                }
            }
            Err(err) => Err(format!("create daemon lock: {err}")),
        }
    }

    fn record_listen_addr(&self, addr: SocketAddr) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.path)
            .map_err(|err| format!("rewrite daemon lock: {err}"))?;
        writeln!(file, "{}", std::process::id())
            .map_err(|err| format!("write daemon lock pid: {err}"))?;
        writeln!(file, "{addr}").map_err(|err| format!("write daemon lock addr: {err}"))?;
        file.flush()
            .map_err(|err| format!("flush daemon lock: {err}"))
    }
}

impl Drop for DaemonLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn lock_path(db_path: &Path) -> PathBuf {
    derived_lock_path(db_path, ".daemon.lock", "daemon.lock")
}

fn runtime_turn_lock_path(db_path: &Path) -> PathBuf {
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

fn create_lock_file(path: &Path) -> std::io::Result<File> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    writeln!(file, "{}", std::process::id())?;
    file.flush()?;
    Ok(file)
}

fn stale_lock_can_be_removed(path: &Path) -> Result<bool, String> {
    let text = fs::read_to_string(path).map_err(|err| format!("read daemon lock: {err}"))?;
    let pid_line = text.lines().next().unwrap_or("");
    let Ok(pid) = pid_line.trim().parse::<u32>() else {
        return Ok(false);
    };
    Ok(!process_exists(pid))
}

fn print_line_now(line: &str) -> Result<(), String> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "{line}").map_err(|err| format!("write daemon status: {err}"))?;
    stdout
        .flush()
        .map_err(|err| format!("flush daemon status: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::effects::{RuntimeEffects, StorageRequirement};
    use crate::core::facts::Fact;
    use crate::core::handle_intent::RecurringIntentSpec;
    use crate::core::intents::{HandlerContext, HandlerResult, Intent, IntentHandler, IntentKind};
    use crate::core::network::{NetworkTarget, OutgoingFrame};
    use crate::core::project_fact::{ProjectionContext, ProjectionOutput, Projector};
    use crate::core::runtime::RuntimeDescription;
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

    #[test]
    fn daemon_turn_profile_formats_recorded_stage_timings() {
        let local_addr = "127.0.0.1:4242".parse().expect("addr");
        let mut profile = DaemonTurnProfile::enabled_for_test(Some(local_addr), false);

        let result = profile
            .measure_bool("stage", || Ok(true))
            .expect("stage result");

        assert!(result);
        let line = profile.finish_line(true).expect("profile line");
        assert!(line.contains("daemon_turn_profile addr=127.0.0.1:4242 active=true"));
        assert!(line.contains("stage_ms="));
        assert!(line.contains("stage_result=1"));
    }

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

    static RECURRING_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);
    static VERSION_REPAIR_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);
    static NORMAL_RECURRING_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);
    static DURABLE_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);
    static VERSION_STORAGE_READY: AtomicBool = AtomicBool::new(false);

    const TEST_RUNTIME: RuntimeDescription = RuntimeDescription {
        schema_sources: &[network::SCHEMA_SOURCE],
        row_mutation_tables: &[],
        projector: noop_projector,
        fact_routes: &[],
        fact_admission: None,
        handlers: &[],
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

    struct VersionRepairHandler;

    impl IntentHandler for VersionRepairHandler {
        fn handle(&self, intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
            assert_eq!(intent.kind.as_str(), "version_repair");
            VERSION_REPAIR_HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
            VERSION_STORAGE_READY.store(true, Ordering::SeqCst);
            Ok(RuntimeEffects::new())
        }
    }

    fn version_repair_handler() -> Box<dyn IntentHandler> {
        Box::new(VersionRepairHandler)
    }

    fn version_repair_builder(
        _store: &Db,
        _context: RecurringIntentContext,
    ) -> Result<Option<Intent>, String> {
        if VERSION_STORAGE_READY.load(Ordering::SeqCst) {
            return Ok(None);
        }
        Ok(Some(Intent::new(
            IntentKind::new("version_repair").expect("intent kind"),
            b"repair".to_vec(),
            Vec::new(),
        )))
    }

    struct NormalRecurringHandler;

    impl IntentHandler for NormalRecurringHandler {
        fn handle(&self, intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
            assert_eq!(intent.kind.as_str(), "normal_recurring");
            NORMAL_RECURRING_HANDLER_CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(RuntimeEffects::new())
        }
    }

    fn normal_recurring_handler() -> Box<dyn IntentHandler> {
        Box::new(NormalRecurringHandler)
    }

    fn normal_recurring_builder(
        _store: &Db,
        _context: RecurringIntentContext,
    ) -> Result<Option<Intent>, String> {
        Ok(Some(Intent::new(
            IntentKind::new("normal_recurring").expect("intent kind"),
            b"normal".to_vec(),
            Vec::new(),
        )))
    }

    fn version_storage_ready(_store: &Db) -> Result<bool, String> {
        Ok(VERSION_STORAGE_READY.load(Ordering::SeqCst))
    }

    const VERSION_GATED_HANDLERS: &[HandlerRoute] = &[
        HandlerRoute {
            intent_kind: "version_repair",
            factory: version_repair_handler,
            storage_requirement: StorageRequirement::MaintenanceBypass,
            recurrence: Some(RecurringIntentSpec {
                build_intent: version_repair_builder,
            }),
        },
        HandlerRoute {
            intent_kind: "normal_recurring",
            factory: normal_recurring_handler,
            storage_requirement: StorageRequirement::MaintenanceBypass,
            recurrence: Some(RecurringIntentSpec {
                build_intent: normal_recurring_builder,
            }),
        },
    ];

    const VERSION_GATED_RUNTIME: RuntimeDescription = RuntimeDescription {
        schema_sources: &[network::SCHEMA_SOURCE],
        row_mutation_tables: &[],
        projector: noop_projector,
        fact_routes: &[],
        fact_admission: None,
        handlers: VERSION_GATED_HANDLERS,
    };

    #[test]
    fn parses_daemon_start_flags() {
        let args = vec![
            "--listen".to_string(),
            "127.0.0.1".to_string(),
            "41000".to_string(),
            "--sync-ms".to_string(),
            "100".to_string(),
            "--quiet-ms".to_string(),
            "200".to_string(),
        ];
        let parsed = parse_start_options(CliArgs::new(&args)).expect("parse");

        assert_eq!(parsed.listen, "127.0.0.1:41000".parse().unwrap());
        assert_eq!(parsed.quiet_ms, 200);
    }

    #[test]
    fn quiet_ms_defaults_to_tick_ms() {
        let args = vec![
            "--listen".to_string(),
            "127.0.0.1".to_string(),
            "41000".to_string(),
            "--sync-ms".to_string(),
            "125".to_string(),
        ];
        let parsed = parse_start_options(CliArgs::new(&args)).expect("parse");

        assert_eq!(parsed.quiet_ms, 125);
    }

    #[test]
    fn lock_paths_derive_from_database_path() {
        let db_path = Path::new("/tmp/topo.db");

        assert_eq!(
            lock_path(db_path),
            PathBuf::from("/tmp/topo.db.daemon.lock")
        );
        assert_eq!(
            runtime_turn_lock_path(db_path),
            PathBuf::from("/tmp/topo.db.runtime.lock")
        );
        assert_eq!(lock_path(Path::new("/")), PathBuf::from("/daemon.lock"));
        assert_eq!(
            runtime_turn_lock_path(Path::new("/")),
            PathBuf::from("/runtime.lock")
        );
    }

    #[test]
    fn active_ticks_run_next_tick_without_injected_sleep() {
        let options = StartOptions {
            listen: "127.0.0.1:41000".parse().unwrap(),
            quiet_ms: 200,
            work_limit: 1,
        };

        assert_eq!(sleep_after_tick(&options, true), None);
        assert_eq!(
            sleep_after_tick(&options, false),
            Some(Duration::from_millis(200))
        );
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
        let mut runtime = Runtime::open_memory(&TEST_RUNTIME).expect("runtime");
        network::queue_outgoing(
            runtime.db(),
            NetworkTarget::new(peer_addr),
            OutgoingFrame {
                bytes: b"tick queued frame".to_vec(),
            },
        )
        .expect("queue outgoing frame");
        let mut scheduler = RecurringScheduler::install(TEST_RUNTIME.handlers);

        let active = runtime_turn(
            DaemonDescription {
                inbound_network_intake: None,
                time_wakes: &[],
                storage_ready: None,
            },
            &mut runtime,
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
        let mut runtime = Runtime::open_memory(&TEST_RUNTIME).expect("runtime");
        let mut scheduler = RecurringScheduler::install(TEST_RUNTIME.handlers);
        runtime.submit_fact(Fact::new(
            crate::core::facts::FactScope::Global,
            7,
            b"one".to_vec(),
        ));
        runtime.submit_fact(Fact::new(
            crate::core::facts::FactScope::Global,
            7,
            b"two".to_vec(),
        ));

        runtime_turn(
            DaemonDescription {
                inbound_network_intake: None,
                time_wakes: &[],
                storage_ready: None,
            },
            &mut runtime,
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

        let local_active = runtime_turn(
            DaemonDescription {
                inbound_network_intake: None,
                time_wakes: &[],
                storage_ready: None,
            },
            &mut runtime,
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
            "local command/query turns must not consume daemon-owned durable work"
        );

        let daemon_active = runtime_turn(
            DaemonDescription {
                inbound_network_intake: None,
                time_wakes: &[],
                storage_ready: None,
            },
            &mut runtime,
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

        let active = runtime_turn(
            DaemonDescription {
                inbound_network_intake: None,
                time_wakes: &[],
                storage_ready: None,
            },
            &mut runtime,
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

        let active = runtime_turn(
            DaemonDescription {
                inbound_network_intake: None,
                time_wakes: &[],
                storage_ready: None,
            },
            &mut runtime,
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
    fn runtime_turn_gives_first_recurring_repair_work_the_storage_ready_barrier() {
        VERSION_REPAIR_HANDLER_CALLS.store(0, Ordering::SeqCst);
        NORMAL_RECURRING_HANDLER_CALLS.store(0, Ordering::SeqCst);
        VERSION_STORAGE_READY.store(false, Ordering::SeqCst);
        let listener =
            network::listen("127.0.0.1:0".parse().expect("listen addr")).expect("daemon listener");
        let mut runtime = Runtime::open_memory(&VERSION_GATED_RUNTIME).expect("runtime");
        let mut scheduler = RecurringScheduler::install(VERSION_GATED_RUNTIME.handlers);

        let status = runtime_turn(
            DaemonDescription {
                inbound_network_intake: None,
                time_wakes: &[],
                storage_ready: Some(version_storage_ready),
            },
            &mut runtime,
            RuntimeTurnHost::daemon(&listener),
            &mut scheduler,
            16,
        )
        .expect("daemon runtime turn");

        assert!(status);
        assert_eq!(VERSION_REPAIR_HANDLER_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(
            NORMAL_RECURRING_HANDLER_CALLS.load(Ordering::SeqCst),
            1,
            "normal recurring work may run only after the first repair handler makes storage ready"
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
