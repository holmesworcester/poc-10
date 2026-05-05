//! Foreground application daemon.
//!
//! The daemon is runtime orchestration around existing protocol workers. It
//! owns a long-lived store handle, a TCP listener, and timing policy. It does
//! not add auth rules, decode event families inline, or bypass the normal
//! command/projector/worker path.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::protocol::cli::Context;
use crate::protocol::event_modules::connection::{types, worker as connection_worker};

const START_USAGE: &str = "start --listen IP PORT [--sync-ms N] [--quiet-ms N]";
const DEFAULT_SYNC_MS: u64 = 250;

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![CliCommand {
        name: "start",
        usage: START_USAGE,
        help: "Run a long-lived TCP sync daemon.",
        run: run_start_command,
    }]
}

fn run_start_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let options = StartOptions::parse(args)?;
    let _lock = DaemonLock::acquire(&context.db_path)?;
    print_line_now(&format!("listening: {}", options.listen))?;
    let output = connection_worker::run(
        &context.store,
        &context.protocol,
        connection_worker::Work::RunDaemon {
            options: types::DaemonOptions {
                listen: options.listen,
                duration: None,
                idle: Duration::from_millis(options.sync_ms),
                ready_batch: connection_worker::DEFAULT_DAEMON_READY_BATCH,
            },
        },
    )?;
    let connection_worker::Output::DaemonRan(report) = output else {
        return Err("connection worker returned non-daemon output".to_string());
    };
    Ok(CliOutput::lines(daemon_lines(&report)))
}

#[derive(Clone, Copy)]
struct StartOptions {
    listen: SocketAddr,
    sync_ms: u64,
}

impl StartOptions {
    fn parse(args: CliArgs<'_>) -> Result<Self, String> {
        let mut listen = None;
        let mut sync_ms = DEFAULT_SYNC_MS;
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
                "--sync-ms" => {
                    sync_ms = parse_positive_u64(args.get(idx + 1), START_USAGE)?;
                    idx += 2;
                }
                "--quiet-ms" => {
                    let _quiet_ms = parse_positive_u64(args.get(idx + 1), START_USAGE)?;
                    idx += 2;
                }
                other => return Err(format!("unknown start option `{other}`\n{START_USAGE}")),
            }
        }
        let listen = listen.ok_or_else(|| START_USAGE.to_string())?;
        Ok(Self { listen, sync_ms })
    }
}

fn daemon_lines(report: &types::DaemonReport) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(local_addr) = report.local_addr {
        lines.push(format!("listening: {local_addr}"));
    }
    lines.extend([
        format!("accepted_connections: {}", report.accepted_connections),
        format!("sync_rounds: {}", report.sync_rounds),
        format!("routes_synced: {}", report.routes_synced),
        format!("failed_routes: {}", report.failed_routes),
        format!("sent_events: {}", report.sent_events),
        format!("received_events: {}", report.received_events),
        format!("ready_events: {}", report.ready_events),
        format!("unblocked_events: {}", report.unblocked_events),
    ]);
    lines
}

fn parse_positive_u64(value: Option<&str>, usage: &str) -> Result<u64, String> {
    let parsed = value
        .ok_or_else(|| usage.to_string())?
        .parse::<u64>()
        .map_err(|_| usage.to_string())?;
    if parsed == 0 {
        return Err(usage.to_string());
    }
    Ok(parsed)
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
        .map(|name| format!("{name}.topo-start.lock"))
        .unwrap_or_else(|| "topo-start.lock".to_string());
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
    let pid_text = fs::read_to_string(path).map_err(|err| format!("read daemon lock: {err}"))?;
    let Ok(pid) = pid_text.trim().parse::<u32>() else {
        return Ok(false);
    };
    Ok(!Path::new(&format!("/proc/{pid}")).exists())
}

fn print_line_now(line: &str) -> Result<(), String> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "{line}").map_err(|err| format!("write daemon status: {err}"))?;
    stdout
        .flush()
        .map_err(|err| format!("flush daemon status: {err}"))
}
