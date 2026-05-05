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
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::core::tcp;
use crate::protocol::cli::Context;
use crate::protocol::event_modules::{connection, sync, worker};

const START_USAGE: &str = "start --listen IP PORT [--sync-ms N] [--quiet-ms N]";
const DEFAULT_SYNC_MS: u64 = 250;
const DEFAULT_ACCEPT_BATCH: usize = 16;
const IDLE_SLEEP_MS: u64 = 25;

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
    let listener = tcp::listen(options.listen)?;
    print_line_now(&format!("listening: {}", listener.local_addr()))?;
    run_loop(context, listener, options)
}

fn run_loop(
    context: &mut Context,
    listener: tcp::Listener,
    options: StartOptions,
) -> Result<CliOutput, String> {
    let sync_every = Duration::from_millis(options.sync_ms);
    let mut last_sync = Instant::now()
        .checked_sub(sync_every)
        .unwrap_or_else(Instant::now);

    loop {
        let served = connection::cli::serve_available(context, &listener, DEFAULT_ACCEPT_BATCH)?;
        if served.accepted_connections > 0 {
            let _ = context.drain_ready_events();
        }

        if last_sync.elapsed() >= sync_every {
            run_sync_tick(context, options.quiet_ms);
            last_sync = Instant::now();
        }

        thread::sleep(Duration::from_millis(IDLE_SLEEP_MS));
    }
}

fn run_sync_tick(context: &mut Context, quiet_ms: u64) {
    if let Err(err) = context.drain_ready_events() {
        eprintln!("daemon: drain ready events: {err}");
        return;
    }

    let start = match context.protocol.modules().maybe_start_sync(
        &context.store,
        current_time_ms(),
        quiet_ms,
    ) {
        Ok(start) => start,
        Err(err) if err.contains("local endpoint is missing") => return,
        Err(err) => {
            eprintln!("daemon: start sync: {err}");
            return;
        }
    };

    if let Err(err) = worker::run(&context.store, &context.protocol, start) {
        eprintln!("daemon: record sync events: {err}");
        return;
    }

    let routes = match context
        .protocol
        .modules()
        .drain_outbox_routes(&context.store)
    {
        Ok(routes) => routes,
        Err(err) if err.contains("local endpoint is missing") => return,
        Err(err) => {
            eprintln!("daemon: drain outbox routes: {err}");
            return;
        }
    };

    for outbound in routes {
        if let Err(err) = connection::cli::exchange_outbound_route(context, outbound) {
            eprintln!("daemon: exchange route: {err}");
        }
    }
}

#[derive(Clone, Copy)]
struct StartOptions {
    listen: SocketAddr,
    sync_ms: u64,
    quiet_ms: u64,
}

impl StartOptions {
    fn parse(args: CliArgs<'_>) -> Result<Self, String> {
        let mut listen = None;
        let mut sync_ms = DEFAULT_SYNC_MS;
        let mut quiet_ms = sync::worker::DEFAULT_QUIET_MS;
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
                    quiet_ms = parse_positive_u64(args.get(idx + 1), START_USAGE)?;
                    idx += 2;
                }
                other => return Err(format!("unknown start option `{other}`\n{START_USAGE}")),
            }
        }
        let listen = listen.ok_or_else(|| START_USAGE.to_string())?;
        Ok(Self {
            listen,
            sync_ms,
            quiet_ms,
        })
    }
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

fn current_time_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn print_line_now(line: &str) -> Result<(), String> {
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    writeln!(stdout, "{line}").map_err(|err| format!("write daemon status: {err}"))?;
    stdout
        .flush()
        .map_err(|err| format!("flush daemon status: {err}"))
}
