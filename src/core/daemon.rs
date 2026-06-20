//! Process lifecycle for a long-running protocol `start` command.
//!
//! The daemon is the reusable process host around a runtime turn. It parses
//! daemon flags, holds the per-database daemon lock, binds the TCP listener,
//! publishes the readiness line, reacts to stop/reset, and repeats a host turn
//! closure until shutdown. The closure is supplied by `core::app`, which already
//! knows the selected protocol description and opened `Runtime`.
//!
//! This file does not define the work performed inside a turn. `core::runtime`
//! owns the bounded turn order, the runtime-turn lock, recurring operational
//! work, projection and intent drains, time-wake admission, and network queue
//! pumping. The daemon supplies only the live listener and cadence for daemon
//! host turns. Local command turns use the same runtime-owned turn machinery
//! without entering this file.
//!
//! `core::app` is the layer above both pieces: it routes `start` to this daemon
//! loop, routes ordinary commands to a local runtime turn plus command dispatch,
//! and wires the protocol's runtime-turn declaration into both paths. Change
//! this file when every long-running daemon process should behave differently;
//! change `runtime.rs` when one turn's queue order or host adapters change; and
//! change `app.rs` when CLI routing or process-level command hosting changes.

use crate::core::cli::{CliArgs, CliOutput};
use crate::core::network;
use crate::core::runtime;
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
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);

static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_termination_signal(_signal: libc::c_int) {
    SHUTDOWN_REQUESTED.store(true, Ordering::SeqCst);
}

// =============================================================================
// Daemon Command Types
// =============================================================================

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

// =============================================================================
// Central Daemon Commands
// =============================================================================

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
        let turn_activity = run_turn(&listener, options.work_limit)?;
        let sleep_after_tick = sleep_after_tick(&options, turn_activity);
        report.ticks += 1;
        std::thread::yield_now();
        if let Some(duration) = sleep_after_tick {
            std::thread::sleep(duration);
        }
    }

    crate::core::perf_profile::emit_runtime_profile(&format!("daemon@{local_addr}"));
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

// =============================================================================
// Start Option Parsing Helpers
// =============================================================================

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
        work_limit: runtime::DEFAULT_WORK_LIMIT,
    })
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

// =============================================================================
// Daemon Loop And Signal Helpers
// =============================================================================

fn sleep_after_tick(options: &StartOptions, active: bool) -> Option<Duration> {
    (!active).then(|| Duration::from_millis(options.quiet_ms))
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

// =============================================================================
// Stop And Reset Helpers
// =============================================================================

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
        runtime::runtime_turn_lock_path(&db_path),
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

// =============================================================================
// Reset Path Helpers
// =============================================================================

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

// =============================================================================
// Stop Process Helpers
// =============================================================================

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

// =============================================================================
// Daemon Lock Helpers
// =============================================================================

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
    derived_lock_path(db_path, ".daemon.lock", "daemon.lock")
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

// =============================================================================
// Output Helpers
// =============================================================================

fn print_line_now(line: &str) -> Result<(), String> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "{line}").map_err(|err| format!("write daemon status: {err}"))?;
    stdout
        .flush()
        .map_err(|err| format!("flush daemon status: {err}"))
}

// =============================================================================
// Tests
// =============================================================================
// Ordered most-central-first: start-option parsing before narrow defaults.
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
        assert_eq!(parsed.quiet_ms, 200);
    }

    #[test]
    fn lock_paths_derive_from_database_path() {
        let db_path = Path::new("/tmp/topo.db");

        assert_eq!(
            lock_path(db_path),
            PathBuf::from("/tmp/topo.db.daemon.lock")
        );
        assert_eq!(
            runtime::runtime_turn_lock_path(db_path),
            PathBuf::from("/tmp/topo.db.runtime.lock")
        );
        assert_eq!(lock_path(Path::new("/")), PathBuf::from("/daemon.lock"));
        assert_eq!(
            runtime::runtime_turn_lock_path(Path::new("/")),
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
}
