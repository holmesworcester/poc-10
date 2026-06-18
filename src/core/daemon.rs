//! Process lifecycle for a long-running protocol `start` command.
//!
//! Core owns only the reusable mechanics: parse daemon flags, hold the
//! per-database lock, bind the TCP listener, publish the readiness line, react to
//! stop/reset, and run a bounded tick from the selected protocol's declarative
//! daemon description. The tick is protocol-agnostic: fire recurring intents,
//! accept network bytes, commit protocol-classified incoming effects, process
//! declared time wakes with a high local budget, drain durable projection, drain
//! incoming projection, drain durable intents, drain local intents, then pump
//! queued outgoing network bytes.
//!
//! The daemon is the host for work that should keep happening without a user
//! command on the stack. It does not decode connection frames or choose protocol
//! actions itself. The protocol declaration turns inbound bytes into runtime
//! effects, declares which time-wake timelines should be admitted, and supplies
//! the runtime handlers that consume queued work.
//!
//! The order inside `tick` is part of the runtime contract. Network input is
//! admitted after recurring intents are fired, due time ranges wake facts,
//! durable projection drains, incoming projection drains, durable intents drain,
//! local intents drain, and then queued outgoing TCP bytes are pumped by target
//! address.
//! Handler-emitted facts remain queued for later projection work. Change that
//! order here only if the whole daemon scheduling policy changes; protocol
//! handlers should adapt by emitting facts, time wakes, or intents rather than
//! calling daemon steps directly.

use crate::core::cli::{CliArgs, CliOutput};
use crate::core::db::Db;
use crate::core::effects::RuntimeEffects;
use crate::core::handle_intent::{
    HandlerRoute, RecurringIntentBuilder, RecurringIntentContext, WorkStatus,
};
use crate::core::network;
use crate::core::project_fact::Timeline;
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
const DEFAULT_WORK_LIMIT: usize = 4096;
const LOCAL_DERIVATION_WORK_MULTIPLIER: usize = 16;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_termination_signal(_signal: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

/// Parsed daemon start options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartOptions {
    /// Address the daemon should bind.
    pub listen: SocketAddr,
    /// Sleep duration after an idle tick.
    pub quiet_ms: u64,
    /// Base maximum queued items one tick should process per side-effecting stage.
    /// Local derivation queues use a larger derived budget.
    pub work_limit: usize,
}

/// Protocol declarations needed by the generic daemon tick.
#[derive(Clone, Copy)]
pub struct DaemonDescription {
    /// Converter from inbound network bytes to protocol-owned runtime effects.
    pub inbound_network_intake: Option<InboundNetworkIntake>,
    /// Time-wake schedules the daemon should admit each tick.
    pub time_wakes: &'static [DaemonTimeWake],
}

/// Function that turns an inbound frame into facts, rows, or follow-up work.
pub type InboundNetworkIntake = fn(InboundNetworkFrame) -> Result<RuntimeEffects, String>;

/// Opaque inbound TCP frame plus local receipt metadata.
#[derive(Debug, Clone)]
pub struct InboundNetworkFrame {
    pub frame: Vec<u8>,
    pub origin_addr: SocketAddr,
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

/// Run one bounded daemon tick.
///
/// The order is fixed: fire recurring intents, accept TCP, commit inbound intake
/// effects, admit time wakes with the high local-derivation budget, drain
/// durable projection, drain incoming projection, drain durable intents, drain
/// local intents, then pump outgoing TCP rows.
/// Protocols should change their declarations rather than reordering this loop.
pub fn tick(
    description: DaemonDescription,
    runtime: &mut Runtime,
    listener: &network::Listener,
    scheduler: &mut RecurringScheduler,
    work_limit: usize,
) -> Result<WorkStatus, String> {
    let mut status = WorkStatus::idle();
    let local_derivation_limit = local_derivation_work_limit(work_limit);
    status.merge(fire_recurring_intents(runtime, scheduler, listener)?);
    status.merge(drain_inbound_listener(
        description,
        runtime,
        listener,
        work_limit,
    )?);
    status.merge(drain_time_wakes(
        description,
        runtime,
        local_derivation_limit,
    )?);
    status.merge(runtime.drain_durable_projection(local_derivation_limit)?);
    status.merge(runtime.drain_incoming_projection(local_derivation_limit)?);
    status.merge(runtime.drain_durable_intents(work_limit)?);
    status.merge(runtime.drain_local_intents(work_limit)?);
    status.merge(drain_outgoing_network(runtime, work_limit)?);
    Ok(status)
}

fn local_derivation_work_limit(work_limit: usize) -> usize {
    work_limit
        .saturating_mul(LOCAL_DERIVATION_WORK_MULTIPLIER)
        .max(work_limit)
}

fn fire_recurring_intents(
    runtime: &mut Runtime,
    scheduler: &mut RecurringScheduler,
    listener: &network::Listener,
) -> Result<WorkStatus, String> {
    let fired = scheduler.fire_due(runtime, now_ms(), Some(listener.local_addr()))?;
    Ok(WorkStatus::progressed(fired > 0))
}

fn drain_inbound_listener(
    description: DaemonDescription,
    runtime: &mut Runtime,
    listener: &network::Listener,
    work_limit: usize,
) -> Result<WorkStatus, String> {
    let Some(intake) = description.inbound_network_intake else {
        return Ok(WorkStatus::idle());
    };
    let accepted = listener.accept_available(work_limit, |source, frame| {
        let effects = intake(InboundNetworkFrame {
            frame,
            origin_addr: source.addr(),
            received_at_local_ms: now_ms(),
        })?;
        if !effects.is_empty() {
            runtime.submit_runtime_effects(effects, "commit inbound network frame")?;
        }
        Ok(())
    })?;
    Ok(WorkStatus::progressed(
        accepted.accepted_connections > 0
            || accepted.value.sent_frames > 0
            || accepted.value.received_frames > 0,
    ))
}

fn drain_time_wakes(
    description: DaemonDescription,
    runtime: &mut Runtime,
    limit: usize,
) -> Result<WorkStatus, String> {
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
    Ok(WorkStatus::progressed(due > 0))
}

fn drain_outgoing_network(runtime: &mut Runtime, work_limit: usize) -> Result<WorkStatus, String> {
    let report = network::pump_outgoing(runtime.db(), work_limit, work_limit)?;
    Ok(WorkStatus::progressed(report.sent_frames > 0))
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// In-memory schedule for the protocol's recurring operational intents.
///
/// Recurring intents are not durable state: the daemon installs these schedules
/// once at startup from the handler registry and fires them on their declared
/// cadence while the process runs. Nothing is persisted, so there is nothing to
/// wipe on upgrade and nothing to replay. The schedules begin firing only after
/// the daemon is running normally, which is after any replay has completed.
pub struct RecurringScheduler {
    schedules: Vec<RecurringSchedule>,
}

struct RecurringSchedule {
    kind: &'static str,
    build_intent: RecurringIntentBuilder,
    interval_ms: u64,
    next_at_ms: u64,
}

impl RecurringScheduler {
    /// Install in-memory schedules for every handler route with a recurrence.
    pub fn install(routes: &'static [HandlerRoute], now_ms: u64) -> Self {
        let schedules = routes
            .iter()
            .filter_map(|route| {
                route.recurrence.map(|spec| RecurringSchedule {
                    kind: route.intent_kind,
                    build_intent: spec.build_intent,
                    interval_ms: spec.interval_ms,
                    next_at_ms: now_ms.saturating_add(spec.initial_delay_ms),
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

    /// Fire every schedule whose next-fire time has arrived.
    ///
    /// Each due schedule builds its current intent from database state and queues it
    /// as live local work for the same tick's drain to dispatch. The builder may
    /// return `None` to skip a tick. Returns the number of intents queued.
    pub fn fire_due(
        &mut self,
        runtime: &mut Runtime,
        now_ms: u64,
        local_addr: Option<SocketAddr>,
    ) -> Result<usize, String> {
        let mut fired = 0;
        for schedule in &mut self.schedules {
            if now_ms < schedule.next_at_ms {
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
            schedule.next_at_ms = now_ms.saturating_add(schedule.interval_ms);
        }
        Ok(fired)
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
    mut tick: impl FnMut(&network::Listener, usize) -> Result<WorkStatus, String>,
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
        let tick_activity = {
            let _turn = RuntimeTurnLock::acquire(db_path)?;
            tick(&listener, options.work_limit)?
        };
        let sleep_after_tick = sleep_after_tick(&options, tick_activity);
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

fn sleep_after_tick(options: &StartOptions, status: WorkStatus) -> Option<Duration> {
    (!status.progressed).then(|| Duration::from_millis(options.quiet_ms))
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

    struct RecurringHandler;

    impl IntentHandler for RecurringHandler {
        fn handle(&self, intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
            assert_eq!(intent.kind.as_str(), "recurring_tick");
            assert_eq!(intent.key, b"cycle".to_vec());
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
            "daemon tick should pass its listen address to recurring builders"
        );
        Ok(Some(Intent::new(
            IntentKind::new("recurring_tick").expect("intent kind"),
            b"cycle".to_vec(),
            Vec::new(),
        )))
    }

    static RECURRING_HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);

    const TEST_RUNTIME: RuntimeDescription = RuntimeDescription {
        schema_sources: &[network::SCHEMA_SOURCE],
        row_mutation_tables: &[],
        projector: noop_projector,
        fact_routes: &[],
        fact_admission: None,
        handlers: &[],
    };

    const RECURRING_HANDLERS: &[HandlerRoute] = &[HandlerRoute {
        intent_kind: "recurring_tick",
        factory: recurring_handler,
        recurrence: Some(RecurringIntentSpec {
            interval_ms: 60_000,
            initial_delay_ms: 0,
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
        let active = WorkStatus {
            progressed: true,
            retried: false,
        };

        assert_eq!(sleep_after_tick(&options, active), None);
        assert_eq!(
            sleep_after_tick(&options, WorkStatus::idle()),
            Some(Duration::from_millis(200))
        );
        assert_eq!(
            sleep_after_tick(
                &options,
                WorkStatus {
                    progressed: false,
                    retried: true,
                },
            ),
            Some(Duration::from_millis(200))
        );
    }

    #[test]
    fn tick_pumps_queued_outgoing_rows_after_runtime_work() {
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
        let mut scheduler = RecurringScheduler::install(TEST_RUNTIME.handlers, now_ms());

        let status = tick(
            DaemonDescription {
                inbound_network_intake: None,
                time_wakes: &[],
            },
            &mut runtime,
            &listener,
            &mut scheduler,
            16,
        )
        .expect("daemon tick");

        assert!(status.progressed);
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
    fn tick_uses_high_local_derivation_budget_for_projection() {
        let listener =
            network::listen("127.0.0.1:0".parse().expect("listen addr")).expect("daemon listener");
        let mut runtime = Runtime::open_memory(&TEST_RUNTIME).expect("runtime");
        let mut scheduler = RecurringScheduler::install(TEST_RUNTIME.handlers, now_ms());
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

        tick(
            DaemonDescription {
                inbound_network_intake: None,
                time_wakes: &[],
            },
            &mut runtime,
            &listener,
            &mut scheduler,
            1,
        )
        .expect("daemon tick");

        assert_eq!(
            runtime.pending_projection_count(),
            0,
            "projection should use the high local-derivation budget, not the base side-effect limit"
        );
    }

    #[test]
    fn tick_fires_recurring_intents_before_drain_steps() {
        RECURRING_HANDLER_CALLS.store(0, Ordering::SeqCst);
        let listener =
            network::listen("127.0.0.1:0".parse().expect("listen addr")).expect("daemon listener");
        let mut runtime = Runtime::open_memory(&RECURRING_RUNTIME).expect("runtime");
        let mut scheduler = RecurringScheduler::install(RECURRING_RUNTIME.handlers, 0);

        let status = tick(
            DaemonDescription {
                inbound_network_intake: None,
                time_wakes: &[],
            },
            &mut runtime,
            &listener,
            &mut scheduler,
            16,
        )
        .expect("daemon tick");

        assert!(status.progressed);
        assert_eq!(RECURRING_HANDLER_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(
            runtime.pending_intent_count(),
            0,
            "the same daemon tick should dispatch the recurring intent it fired"
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
