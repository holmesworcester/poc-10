//! Process lifecycle for a long-running protocol `start` command.
//!
//! Core owns only the reusable mechanics: parse daemon flags, hold the
//! per-store lock, bind the TCP listener, publish the readiness line, react to
//! stop/reset, and run a bounded tick from the selected protocol's declarative
//! daemon description. The tick is protocol-agnostic: accept network bytes,
//! admit declared inbound intents, process declared time wakes, run
//! projection/intent/projection work, then delete claimed inbound bytes only
//! after receive dispatch did not ask to retry.

use crate::core::cli::{CliArgs, CliOutput};
use crate::core::intents::Intent;
use crate::core::network;
use crate::core::projectors::Timeline;
use crate::core::runtime::Runtime;
use crate::core::store::Store;
use crate::core::tcp;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

const START_USAGE: &str = "start --listen IP PORT [--tick-ms N] [--quiet-ms N]";
const STOP_USAGE: &str = "stop";
const RESET_USAGE: &str = "reset";
const DEFAULT_TICK_MS: u64 = 250;
const DEFAULT_WORK_LIMIT: usize = 4096;
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_termination_signal(_signal: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartOptions {
    pub listen: SocketAddr,
    pub tick_ms: u64,
    pub quiet_ms: u64,
    pub work_limit: usize,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TickActivity {
    pub active: bool,
}

impl TickActivity {
    pub fn active() -> Self {
        Self { active: true }
    }

    pub fn idle() -> Self {
        Self { active: false }
    }

    pub fn from_bool(active: bool) -> Self {
        Self { active }
    }
}

#[derive(Clone, Copy)]
pub struct DaemonDescription {
    pub inbound_network_intent: Option<InboundNetworkIntent>,
    pub time_wakes: &'static [DaemonTimeWake],
}

pub type InboundNetworkIntent = fn(InboundNetworkFrame) -> Result<Intent, String>;

#[derive(Debug, Clone)]
pub struct InboundNetworkFrame {
    pub frame: Vec<u8>,
    pub origin_addr: SocketAddr,
    pub received_at_local_ms: u64,
}

#[derive(Clone, Copy)]
pub struct DaemonTimeWake {
    pub timeline: fn() -> Timeline,
    pub end_inclusive: fn(&Store) -> Result<Option<u64>, String>,
}

pub fn tick(
    description: DaemonDescription,
    runtime: &mut Runtime,
    listener: &tcp::Listener,
    work_limit: usize,
) -> Result<TickActivity, String> {
    let accepted = accept_inbound_network(description, runtime, listener, work_limit)?;
    let inbound = claim_inbound_network(description, runtime, work_limit)?;
    submit_inbound_network_intents(description, runtime, &inbound)?;

    let due_time_wakes = process_declared_time_wakes(description, runtime, work_limit)?;
    let projection_before_handlers = runtime.process_projection_until_idle(4, work_limit)?;
    let dispatched = runtime.dispatch_intents(work_limit)?;
    let projection_after_handlers = runtime.process_projection_until_idle(4, work_limit)?;
    delete_claimed_inbound_after_successful_dispatch(runtime, &inbound, dispatched.retried)?;

    Ok(TickActivity::from_bool(
        accepted.accepted_connections > 0
            || accepted.value.sent_frames > 0
            || accepted.value.received_frames > 0
            || !inbound.is_empty()
            || due_time_wakes > 0
            || !projection_before_handlers.is_idle()
            || !dispatched.is_idle()
            || !projection_after_handlers.is_idle(),
    ))
}

fn accept_inbound_network(
    description: DaemonDescription,
    runtime: &Runtime,
    listener: &tcp::Listener,
    work_limit: usize,
) -> Result<tcp::AcceptReport<tcp::StreamReport>, String> {
    if description.inbound_network_intent.is_none() {
        return Ok(tcp::AcceptReport {
            accepted_connections: 0,
            value: tcp::StreamReport::default(),
        });
    }
    listener.accept_available(runtime.store(), work_limit)
}

fn claim_inbound_network(
    description: DaemonDescription,
    runtime: &Runtime,
    work_limit: usize,
) -> Result<Vec<network::InboundNetworkRow>, String> {
    if description.inbound_network_intent.is_none() {
        return Ok(Vec::new());
    }
    network::claim_inbound(runtime.store(), work_limit)
}

fn submit_inbound_network_intents(
    description: DaemonDescription,
    runtime: &mut Runtime,
    inbound: &[network::InboundNetworkRow],
) -> Result<(), String> {
    let Some(to_intent) = description.inbound_network_intent else {
        return Ok(());
    };
    let received_at_local_ms = now_ms();
    for row in inbound {
        runtime.submit_intent(to_intent(InboundNetworkFrame {
            frame: row.bytes.clone(),
            origin_addr: row.source.addr(),
            received_at_local_ms,
        })?)?;
    }
    Ok(())
}

fn process_declared_time_wakes(
    description: DaemonDescription,
    runtime: &mut Runtime,
    work_limit: usize,
) -> Result<usize, String> {
    let mut due = 0;
    for wake in description.time_wakes {
        let Some(end_inclusive) = (wake.end_inclusive)(runtime.store())? else {
            continue;
        };
        due += runtime.process_due_time_range((wake.timeline)(), None, end_inclusive, work_limit);
    }
    Ok(due)
}

fn delete_claimed_inbound_after_successful_dispatch(
    runtime: &Runtime,
    inbound: &[network::InboundNetworkRow],
    retried: bool,
) -> Result<(), String> {
    if !retried {
        network::delete_inbound(runtime.store(), inbound)?;
    }
    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DaemonReport {
    pub local_addr: Option<SocketAddr>,
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

pub fn start(
    db_path: &Path,
    args: CliArgs<'_>,
    mut tick: impl FnMut(&tcp::Listener, usize) -> Result<TickActivity, String>,
) -> Result<CliOutput, String> {
    let options = parse_start_options(args)?;
    SHUTDOWN_REQUESTED.store(false, Ordering::SeqCst);
    install_termination_handlers();

    let lock = DaemonLock::acquire(db_path)?;
    let listener = tcp::listen(options.listen)?;
    let local_addr = listener.local_addr();
    lock.record_listen_addr(local_addr)?;
    print_line_now(&format!("listening: {local_addr}"))?;

    let mut report = DaemonReport {
        local_addr: Some(local_addr),
        ..DaemonReport::default()
    };
    while !SHUTDOWN_REQUESTED.load(Ordering::SeqCst) {
        let tick_activity = tick(&listener, options.work_limit)?;
        let sleep_after_tick = sleep_after_tick(&options, tick_activity);
        report.ticks += 1;
        if let Some(duration) = sleep_after_tick {
            std::thread::sleep(duration);
        }
    }

    Ok(CliOutput::lines(report.lines()))
}

pub fn stop(db_path: &Path, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(0, STOP_USAGE)?;
    Ok(CliOutput::lines(stop_daemon(db_path)?))
}

pub fn reset(db_path: &Path, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(0, RESET_USAGE)?;
    let mut lines = stop_daemon(db_path)?;
    lines.extend(reset_db_files(db_path)?);
    Ok(CliOutput::lines(lines))
}

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
        tick_ms,
        quiet_ms: quiet_ms.unwrap_or(tick_ms),
        work_limit: DEFAULT_WORK_LIMIT,
    })
}

fn sleep_after_tick(options: &StartOptions, tick: TickActivity) -> Option<Duration> {
    (!tick.active).then(|| Duration::from_millis(options.quiet_ms))
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
    let mut path = db_path.to_path_buf();
    let lock_name = db_path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| format!("{name}.daemon.lock"))
        .unwrap_or_else(|| "daemon.lock".to_string());
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
        assert_eq!(parsed.tick_ms, 100);
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

        assert_eq!(parsed.tick_ms, 125);
        assert_eq!(parsed.quiet_ms, 125);
    }

    #[test]
    fn active_ticks_run_next_tick_without_injected_sleep() {
        let options = StartOptions {
            listen: "127.0.0.1:41000".parse().unwrap(),
            tick_ms: 100,
            quiet_ms: 200,
            work_limit: 1,
        };
        let active = TickActivity::active();

        assert_eq!(sleep_after_tick(&options, active), None);
        assert_eq!(
            sleep_after_tick(&options, TickActivity::idle()),
            Some(Duration::from_millis(200))
        );
    }
}
