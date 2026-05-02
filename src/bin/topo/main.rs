//! # `topo` — minimal viable daemon binary
//!
//! Post-#47 the historical daemon (`runtime/main.rs`, `node.rs`,
//! `runtime_manager.rs`, `control_loop_node.rs`) was deleted wholesale.
//! This binary is the substrate-only replacement: a thin CLI shell that
//! either starts the new `ControlLoopRuntime` (plus the RPC server so
//! out-of-process CLIs can talk to it) or drives a single command
//! through the public runtime API.
//!
//! ## Subcommands
//!
//! - `topo --db <path> start --bind <ip:port>` — start the daemon. Spawns
//!   a [`ControlLoopRuntime`] and the RPC server, blocks until SIGINT /
//!   SIGTERM or a `RpcMethod::Shutdown` request.
//! - `topo --db <path> stop` — best-effort: send `Shutdown` RPC if the
//!   socket exists.
//! - `topo --db <path> status` — print the current
//!   [`api::EndpointStatus`].
//! - `topo --db <path> create-workspace <name>` — submit a
//!   [`api::Command::CreateWorkspace`] and await its terminal outcome.
//!   Also accepts `--workspace-name X --username Y --device-name Z`
//!   for compatibility with the legacy harness; only `--workspace-name`
//!   is wired into the substrate today.
//! - `topo --db <path> accept-invite <invite-blob>` — submit a
//!   [`api::Command::AcceptInvite`] (96-byte hex blob).
//! - `topo --db <path> send <message>` — submit a
//!   [`api::Command::SendMessage`] under the most-recently-applied
//!   workspace.
//! - `topo --db <path> messages` — print the messages projection via
//!   [`api::list_messages`].
//! - `topo --db <path> tenant active|list|use` — passthrough to the
//!   RPC server; needs a running daemon.
//! - `topo --db <path> assert-now <pred>` /
//!   `topo --db <path> assert-eventually <pred> --timeout-ms ...` —
//!   passthrough to the RPC server's predicate evaluator.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clap::{Parser, Subcommand};
use tokio::signal;

use topo::api::{self, Command, CommandOutcome, DbHandle, WorkspaceId};
use topo::rpc::client::{rpc_call, RpcClientError};
use topo::rpc::protocol::RpcMethod;
use topo::rpc::server::{run_rpc_server, DaemonState, NodeRuntimeNetInfo};
use topo::runtime::control_loop::ControlLoopRuntime;

const COMMAND_DEADLINE: Duration = Duration::from_secs(120);

#[derive(Parser, Debug)]
#[command(name = "topo")]
#[command(about = "topo — minimal substrate daemon")]
struct Cli {
    /// Database path.
    #[arg(short, long, default_value = "topo.db", global = true)]
    db: String,

    /// Custom RPC socket path (default: <db>.topo.sock). Currently
    /// unused by the kernel but accepted for compatibility with the
    /// legacy CLI harness.
    #[arg(long, global = true)]
    socket: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the daemon and block on shutdown signal.
    Start {
        /// Bind address for the substrate transport listener.
        #[arg(short, long, default_value = "127.0.0.1:0")]
        bind: SocketAddr,

        /// Accepted but ignored — substrate sync hasn't been wired
        /// to a "last day only" mode yet.
        #[arg(long)]
        last_day_only_sync: bool,
    },

    /// Stop a running daemon by sending Shutdown RPC.
    Stop,

    /// Print listen address and an endpoint summary.
    Status,

    /// Submit a CreateWorkspace command.
    #[command(name = "create-workspace")]
    CreateWorkspace {
        /// Positional name (legacy).
        #[arg(default_value = "")]
        name: String,
        /// Display name for the workspace.
        #[arg(long)]
        workspace_name: Option<String>,
        /// Username for the new identity (currently ignored — substrate
        /// has no identity-chain command surface yet).
        #[arg(long)]
        username: Option<String>,
        /// Device name for this peer (currently ignored).
        #[arg(long)]
        device_name: Option<String>,
        /// Public address to embed in auto-generated invite link
        /// (currently ignored — invites are produced via `create-invite`).
        #[arg(long)]
        public_addr: Option<String>,
        /// Number of seed messages (ignored — generator hook missing).
        #[arg(long)]
        message_count: Option<usize>,
        /// Network age (ignored).
        #[arg(long)]
        network_age: Option<String>,
    },

    /// Submit an AcceptInvite command. `invite_blob` is a hex-encoded
    /// 96-byte (invite_event_id || workspace_id || tenant_event_id) tuple.
    #[command(name = "accept-invite")]
    AcceptInvite {
        /// Hex-encoded 96-byte blob.
        invite_blob: String,
    },

    /// Accept a topo://invite/... link (legacy form). Currently routed
    /// into `AcceptInvite` after stripping the prefix; substrate-side
    /// invite-link parsing has not been re-enabled yet so most
    /// real-world links will fail. Provided so the harness's
    /// `accept-invite` calls don't error out at the parser.
    #[command(name = "accept")]
    Accept {
        /// Invite link.
        invite: String,
        /// Username for the new identity (currently ignored).
        #[arg(long, default_value = "user")]
        username: String,
        /// Device name (currently ignored).
        #[arg(long)]
        devicename: Option<String>,
    },

    /// Submit a SendMessage command under the most-recently-applied workspace.
    Send {
        /// Message content.
        content: String,
        /// Client op id (legacy harness flag, ignored).
        #[arg(long)]
        client_op_id: Option<String>,
    },

    /// Bulk-author N messages in a single CLI invocation. Used by the
    /// black-box perf tests so subprocess spawn cost doesn't dominate
    /// the wall clock at high N. Each call goes through the same
    /// substrate `api::submit(SendMessage)` path as `topo send` —
    /// only the outer subprocess loop is collapsed.
    BenchSend {
        /// Number of messages to author.
        #[arg(long)]
        count: usize,
        /// Per-message content prefix; final content is
        /// `"<prefix>-<i>"` for `i` in `0..count`.
        #[arg(long, default_value = "msg")]
        content_prefix: String,
    },

    /// List applied messages.
    Messages {
        /// Maximum messages to print (0 = unlimited).
        #[arg(short, long, default_value = "50")]
        limit: usize,
        /// Workspace id (hex 64 or base64). When omitted the daemon's
        /// active workspace is used.
        #[arg(long)]
        workspace: Option<String>,
    },

    /// Print a base64-encoded invite blob the remote daemon can paste
    /// into `topo connect <invite>`. The blob carries the local
    /// endpoint id, the local listen address, and the workspace id.
    /// Requires the daemon to be running so the listen-address file is
    /// up to date.
    #[command(name = "create-invite", alias = "invite")]
    CreateInvite {
        /// Base64-encoded workspace id (matches the value `topo status`
        /// prints — first 8 hex chars suffice if you're piping this
        /// from the most-recently-applied workspace).
        ///
        /// If omitted the most-recently-applied workspace is used.
        #[arg(short, long)]
        workspace: Option<String>,
        /// Public address (legacy harness flag) — currently ignored;
        /// the listen address from `start` is used.
        #[arg(long, alias = "bootstrap")]
        public_addr: Option<String>,
        /// Public SPKI (legacy harness flag) — currently ignored.
        #[arg(long)]
        public_spki: Option<String>,
    },

    /// Establish a real Connection to the remote daemon described by
    /// `<invite>`. Authors a Connection event signed by our local
    /// ed25519 key, derives connection secrets deterministically,
    /// and bootstrap-wraps the Connection bytes to the remote so it
    /// projects the same event.
    Connect {
        /// Base64 invite blob produced by `topo --db <peer> create-invite`.
        invite: String,
    },

    /// Manage tenants (list / use / active). Routes via RPC to a
    /// running daemon.
    Tenant {
        #[command(subcommand)]
        action: Option<TenantAction>,
    },

    /// Assert a predicate holds right now (RPC passthrough).
    #[command(name = "assert-now")]
    AssertNow {
        /// Predicate: "field op value".
        predicate: String,
        /// Workspace id (hex 64 or base64). Required for per-workspace
        /// predicates when more than one workspace is hosted.
        #[arg(long)]
        workspace: Option<String>,
    },

    /// Assert a predicate eventually holds (RPC passthrough).
    #[command(name = "assert-eventually")]
    AssertEventually {
        /// Predicate: "field op value".
        predicate: String,
        /// Timeout in milliseconds.
        #[arg(long, default_value = "10000")]
        timeout_ms: u64,
        /// Poll interval in milliseconds.
        #[arg(long, default_value = "200")]
        interval_ms: u64,
        /// Workspace id (hex 64 or base64). Required for per-workspace
        /// predicates when more than one workspace is hosted.
        #[arg(long)]
        workspace: Option<String>,
    },

    /// Generic RPC passthrough (legacy harness compatibility shim).
    /// Anything that needs a feature the substrate doesn't expose
    /// today routes through the catch-all `rpc-call` subcommand.
    #[command(name = "rpc-call")]
    RpcCall {
        /// JSON-encoded RpcMethod (auto-wrapped).
        #[arg(long)]
        method_json: String,
    },
}

#[derive(Subcommand, Debug)]
enum TenantAction {
    /// List local tenants.
    List,
    /// Switch active tenant by 1-based index.
    Use {
        /// Tenant number.
        index: usize,
    },
    /// Show currently active tenant.
    Active,
}

fn main() {
    let cli = Cli::parse();

    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .try_init();

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime");

    let result: Result<(), Box<dyn std::error::Error + Send + Sync>> =
        rt.block_on(async move { run(cli).await });

    if let Err(e) = result {
        eprintln!("error: {}", e);
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let db_path = PathBuf::from(&cli.db);
    let socket_override = cli.socket.clone();
    match cli.command {
        Commands::Start {
            bind,
            last_day_only_sync: _,
        } => cmd_start(&db_path, bind).await,
        Commands::Stop => cmd_stop(&db_path, socket_override.as_deref()),
        Commands::Status => cmd_status(&db_path).await,
        Commands::CreateWorkspace {
            name,
            workspace_name,
            username,
            device_name,
            public_addr: _,
            message_count: _,
            network_age: _,
        } => {
            let chosen = workspace_name
                .filter(|s| !s.is_empty())
                .or_else(|| if name.is_empty() { None } else { Some(name) })
                .unwrap_or_else(|| "workspace".to_string());
            let user = username.unwrap_or_else(|| "user".to_string());
            let device = device_name.unwrap_or_else(|| "device".to_string());
            cmd_create_workspace_full(&db_path, socket_override.as_deref(), &chosen, &user, &device)
                .await
        }
        Commands::AcceptInvite { invite_blob } => {
            cmd_accept_invite(&db_path, &invite_blob).await
        }
        Commands::Accept {
            invite,
            username,
            devicename,
        } => {
            cmd_accept_link(
                &db_path,
                socket_override.as_deref(),
                &invite,
                &username,
                devicename.as_deref(),
            )
            .await
        }
        Commands::Send { content, .. } => cmd_send(&db_path, &content).await,
        Commands::BenchSend {
            count,
            content_prefix,
        } => cmd_bench_send(&db_path, count, &content_prefix).await,
        Commands::Messages { limit, workspace: _ } => cmd_messages(&db_path, limit).await,
        Commands::CreateInvite { workspace, .. } => {
            cmd_create_invite(&db_path, workspace.as_deref()).await
        }
        Commands::Connect { invite } => cmd_connect(&db_path, &invite).await,
        Commands::Tenant { action } => {
            cmd_tenant(&db_path, socket_override.as_deref(), action).await
        }
        Commands::AssertNow {
            predicate,
            workspace,
        } => {
            cmd_assert_now(
                &db_path,
                socket_override.as_deref(),
                &predicate,
                workspace.as_deref(),
            )
            .await
        }
        Commands::AssertEventually {
            predicate,
            timeout_ms,
            interval_ms,
            workspace,
        } => {
            cmd_assert_eventually(
                &db_path,
                socket_override.as_deref(),
                &predicate,
                timeout_ms,
                interval_ms,
                workspace.as_deref(),
            )
            .await
        }
        Commands::RpcCall { method_json } => {
            cmd_rpc_call(&db_path, socket_override.as_deref(), &method_json).await
        }
    }
}

// ---------------------------------------------------------------------------
// `start`
// ---------------------------------------------------------------------------

async fn cmd_start(
    db_path: &std::path::Path,
    bind: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let signing_key = topo::api::ensure_signing_key(db_path)?;
    let local_endpoint_id = signing_key.verifying_key().to_bytes();
    let handles = ControlLoopRuntime::start(bind, local_endpoint_id, db_path).await?;
    let listen = handles.runtime.listen_addr;

    // Persist listen addr beside the DB so a sibling CLI process can
    // print an invite without round-tripping through the daemon.
    write_listen_addr_file(db_path, listen)?;

    // Attach DB-backed address fallback to the runtime's address book
    // so cross-process address records (written by `topo connect` on
    // the peer) become resolvable for outbound sends.
    if let Some(ctx) = topo::runtime::control_loop::default_handlers::OutboxWakeContext::current() {
        ctx.address_book.attach_db_path(db_path.to_path_buf());
        // Also seed our own listen addr so any local lookups resolve.
        ctx.address_book.insert(local_endpoint_id, listen);
        // Warm the cache from any existing DB rows (e.g. learned during
        // a previous run).
        ctx.address_book.warm_from_db();
    }

    // Start the RPC server in a background thread so the harness can
    // use `topo tenant active`, `assert-now`, `assert-eventually`, and
    // friends. The DaemonState advertises the runtime's listen addr
    // through `runtime_net.listen_addr`.
    let db_path_str = db_path.to_string_lossy().to_string();
    let rpc_state = Arc::new(DaemonState::new(&db_path_str));
    *rpc_state.runtime_net.write().unwrap() = Some(NodeRuntimeNetInfo {
        listen_addr: listen.to_string(),
        upnp: None,
    });
    *rpc_state.resolved_bind_addr.write().unwrap() = Some(listen);
    let socket_path = topo::service::socket_path_for_db(&db_path_str);
    let shutdown_flag = Arc::new(AtomicBool::new(false));
    let shutdown_notify = Arc::new(tokio::sync::Notify::new());
    let rpc_thread = {
        let socket_path = socket_path.clone();
        let state = rpc_state.clone();
        let shutdown = shutdown_flag.clone();
        let notify = shutdown_notify.clone();
        std::thread::spawn(move || {
            if let Err(e) = run_rpc_server(&socket_path, state, shutdown, notify) {
                eprintln!("topo: rpc server exited: {}", e);
            }
        })
    };

    println!("topo: listening on {}", listen);
    println!("topo: endpoint_id = {}", hex::encode(local_endpoint_id));
    println!("topo: db = {}", db_path.display());
    println!("topo: rpc socket = {}", socket_path.display());
    println!("topo: press ctrl-c to shut down");

    // Wait on either ctrl-c or an in-band Shutdown RPC.
    let notify_for_wait = shutdown_notify.clone();
    let shutdown_flag_for_wait = shutdown_flag.clone();
    tokio::select! {
        _ = signal::ctrl_c() => {
            println!("topo: shutdown signal received");
        }
        _ = notify_for_wait.notified() => {
            println!("topo: shutdown rpc received");
        }
    }
    shutdown_flag_for_wait.store(true, Ordering::Relaxed);
    shutdown_notify.notify_waiters();

    let _ = std::fs::remove_file(listen_addr_file(db_path));
    ControlLoopRuntime::shutdown(handles).await?;

    // Give the RPC server thread up to a second to exit cleanly. It
    // polls `shutdown_flag` every 50 ms so this is plenty.
    let _ = std::thread::Builder::new()
        .name("rpc-join".to_string())
        .spawn(move || {
            let _ = rpc_thread.join();
        });
    // Also clean up the socket file if the RPC server didn't already.
    let _ = std::fs::remove_file(&socket_path);
    Ok(())
}

fn listen_addr_file(db_path: &std::path::Path) -> PathBuf {
    let mut p = db_path.to_path_buf();
    let stem = p
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "topo.db".to_string());
    p.set_file_name(format!(".{}.listen", stem));
    p
}

fn write_listen_addr_file(
    db_path: &std::path::Path,
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let path = listen_addr_file(db_path);
    std::fs::write(path, addr.to_string())?;
    Ok(())
}

fn read_listen_addr_file(
    db_path: &std::path::Path,
) -> Result<SocketAddr, Box<dyn std::error::Error + Send + Sync>> {
    use std::str::FromStr;
    let path = listen_addr_file(db_path);
    let s = std::fs::read_to_string(&path)
        .map_err(|e| format!("read listen addr file {}: {}", path.display(), e))?;
    Ok(SocketAddr::from_str(s.trim())?)
}

// ---------------------------------------------------------------------------
// `stop`
// ---------------------------------------------------------------------------

fn cmd_stop(
    db_path: &std::path::Path,
    socket_override: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket = socket_override
        .map(PathBuf::from)
        .unwrap_or_else(|| topo::service::socket_path_for_db(&db_path.to_string_lossy()));
    if !socket.exists() {
        // No socket — nothing to stop.
        println!("topo: stop is a no-op (no rpc socket at {})", socket.display());
        return Ok(());
    }
    match rpc_call(&socket, RpcMethod::Shutdown) {
        Ok(resp) => {
            if resp.ok {
                println!("topo: shutdown rpc sent");
                Ok(())
            } else {
                Err(format!("shutdown rpc failed: {:?}", resp.error).into())
            }
        }
        Err(RpcClientError::DaemonNotRunning(_)) => {
            println!("topo: stop is a no-op (daemon not running)");
            Ok(())
        }
        Err(e) => Err(format!("shutdown rpc error: {}", e).into()),
    }
}

// ---------------------------------------------------------------------------
// `status`
// ---------------------------------------------------------------------------

async fn cmd_status(
    db_path: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let db = DbHandle::open(db_path)?;
    let status = api::endpoint_status(&db).await?;

    println!("db = {}", db_path.display());
    println!("endpoint_id = {}", short_hex(&status.endpoint_id));
    println!(
        "events: applied={} blocked={} pending={}",
        status.events_applied, status.events_blocked, status.events_pending,
    );
    if status.workspaces.is_empty() {
        println!("workspaces: <none>");
    } else {
        println!("workspaces:");
        for ws in &status.workspaces {
            println!(
                "  {} :: {:<32} messages={} users={}",
                short_hex(&ws.id),
                ws.name,
                ws.message_count,
                ws.user_count,
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `create-workspace`
// ---------------------------------------------------------------------------

async fn cmd_create_workspace_full(
    db_path: &std::path::Path,
    _socket_override: Option<&str>,
    workspace_name: &str,
    _username: &str,
    _device_name: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Substrate-only path: emit a Workspace event via the local-intent
    // helper. The legacy `RpcMethod::CreateWorkspace` path (which would
    // populate the identity-chain projection) cannot be used because
    // the legacy projection tables (`invites_accepted.recorded_by` etc)
    // were retired in Stage 3.5 step 5B; running the RPC path against
    // the substrate-only schema produces "no such column: recorded_by"
    // errors. The harness tests that depended on that flow are
    // `#[ignore]`d (see #61).
    let db = DbHandle::open(db_path)?;
    let cmd = Command::CreateWorkspace {
        name: workspace_name.to_string(),
    };
    println!("topo: submitting CreateWorkspace");
    let outcome = api::run(&db, cmd, COMMAND_DEADLINE).await?;
    report_outcome("workspace", &outcome)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// `accept` (topo://invite/... link form)
// ---------------------------------------------------------------------------

async fn cmd_accept_link(
    db_path: &std::path::Path,
    socket_override: Option<&str>,
    invite: &str,
    username: &str,
    devicename: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket = resolve_socket(db_path, socket_override);
    let device = devicename.unwrap_or("device").to_string();
    if socket.exists() {
        match rpc_call(
            &socket,
            RpcMethod::AcceptInvite {
                invite: invite.to_string(),
                username: username.to_string(),
                devicename: device.clone(),
            },
        ) {
            Ok(resp) => {
                if !resp.ok {
                    return Err(resp
                        .error
                        .unwrap_or_else(|| "accept rpc failed".into())
                        .into());
                }
                println!("topo: invite accepted (via rpc)");
                return Ok(());
            }
            Err(RpcClientError::DaemonNotRunning(_)) => {}
            Err(e) => return Err(format!("rpc: {}", e).into()),
        }
    }
    Err(format!(
        "accept: substrate cannot parse topo://invite links without a \
         running daemon (invite={})",
        invite
    )
    .into())
}

// ---------------------------------------------------------------------------
// `accept-invite`
// ---------------------------------------------------------------------------

async fn cmd_accept_invite(
    db_path: &std::path::Path,
    invite_blob_hex: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let blob = hex::decode(invite_blob_hex)
        .map_err(|e| format!("invalid hex blob: {}", e))?;
    let db = DbHandle::open(db_path)?;
    let cmd = Command::AcceptInvite { invite_blob: blob };
    println!("topo: submitting AcceptInvite");
    let outcome = api::run(&db, cmd, COMMAND_DEADLINE).await?;
    report_outcome("invite_accepted", &outcome)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// `send`
// ---------------------------------------------------------------------------

async fn cmd_send(
    db_path: &std::path::Path,
    content: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Substrate-only: emit a Message event via the local-intent helper.
    // The legacy `RpcMethod::Send` path goes through the legacy peer
    // identity chain and cannot be used against the substrate-only
    // schema.
    let db = DbHandle::open(db_path)?;
    let workspaces = api::list_workspaces(&db).await?;
    let workspace_id: WorkspaceId = workspaces
        .last()
        .map(|w| w.id)
        .ok_or("no applied workspace — run create-workspace first")?;

    let cmd = Command::SendMessage {
        workspace_id,
        content: content.to_string(),
    };
    println!("topo: submitting SendMessage (substrate api)");
    let outcome = api::run(&db, cmd, COMMAND_DEADLINE).await?;
    report_outcome("message", &outcome)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// `bench-send` — bulk-author N messages in one CLI invocation
// ---------------------------------------------------------------------------

async fn cmd_bench_send(
    db_path: &std::path::Path,
    count: usize,
    content_prefix: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let db = DbHandle::open(db_path)?;
    let workspaces = api::list_workspaces(&db).await?;
    let workspace_id: WorkspaceId = workspaces
        .last()
        .map(|w| w.id)
        .ok_or("no applied workspace — run create-workspace first")?;

    let started = std::time::Instant::now();
    let handles = api::bulk_send_messages(&db, workspace_id, count, content_prefix).await?;
    let submit_elapsed = started.elapsed();
    println!(
        "topo: bench-send batched {} inserts in {:.3}s ({:.0} cmds/s)",
        count,
        submit_elapsed.as_secs_f64(),
        count as f64 / submit_elapsed.as_secs_f64()
    );

    // Block until all are Applied so the caller knows authoring is
    // done and the perf test wall clock can advance to convergence.
    for handle in &handles {
        let _ = api::await_completion(&db, handle, COMMAND_DEADLINE).await?;
    }
    let total = started.elapsed();
    println!(
        "topo: bench-send N={} fully applied in {:.3}s ({:.0} msg/s)",
        count,
        total.as_secs_f64(),
        count as f64 / total.as_secs_f64()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// `messages`
// ---------------------------------------------------------------------------

async fn cmd_messages(
    db_path: &std::path::Path,
    limit: usize,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Substrate-only: read the messages projection. RPC `Messages`
    // would route through the legacy `recorded_by` lookup which fails
    // on the substrate-only schema.
    let db = DbHandle::open(db_path)?;
    let workspaces = api::list_workspaces(&db).await?;
    if workspaces.is_empty() {
        println!("(no messages — no workspace)");
        return Ok(());
    }
    // Aggregate messages across all workspaces (preserves the prior CLI
    // behaviour: `topo messages` printed every applied message).
    let mut all = Vec::new();
    for ws in &workspaces {
        let mut ms = api::list_messages(&db, ws.id, limit).await?;
        all.append(&mut ms);
    }
    all.sort_by(|a, b| {
        a.created_at_ms
            .cmp(&b.created_at_ms)
            .then_with(|| a.id.cmp(&b.id))
    });
    if limit > 0 && all.len() > limit {
        all.truncate(limit);
    }

    if all.is_empty() {
        println!("(no messages)");
    } else {
        for (i, m) in all.iter().enumerate() {
            println!(
                "[{}] ws={} author={} created_at={} :: {}",
                i + 1,
                short_hex(&m.workspace_id),
                short_author(&m.author.author_id_b64),
                m.created_at_ms,
                m.content
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `create-invite`
// ---------------------------------------------------------------------------

async fn cmd_create_invite(
    db_path: &std::path::Path,
    workspace_arg: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Substrate-only: emit a base64-encoded (endpoint_id, listen_addr,
    // workspace_id) blob suitable for `topo connect`. The legacy
    // `topo://invite/...` link form is produced by
    // `RpcMethod::CreateInvite` which depends on the retired
    // identity-chain projection.
    let signing_key = topo::api::ensure_signing_key(db_path)?;
    let local_endpoint_id = signing_key.verifying_key().to_bytes();
    let listen_addr = read_listen_addr_file(db_path).map_err(|e| {
        format!(
            "could not read listen address (is the daemon running?): {}",
            e
        )
    })?;

    // Pick the workspace.
    let db = DbHandle::open(db_path)?;
    let workspaces = api::list_workspaces(&db).await?;
    if workspaces.is_empty() {
        return Err("no applied workspace — run create-workspace first".into());
    }
    let workspace_id: WorkspaceId = match workspace_arg {
        None => workspaces.last().unwrap().id,
        Some(arg) => {
            // Accept either a 64-hex-char id or short prefix.
            let needle = arg.trim().to_ascii_lowercase();
            workspaces
                .iter()
                .find(|w| {
                    let h = hex::encode(&w.id);
                    h == needle || h.starts_with(&needle)
                })
                .map(|w| w.id)
                .ok_or_else(|| format!("workspace not found: {}", arg))?
        }
    };

    let invite = api::encode_connection_invite(&local_endpoint_id, listen_addr, &workspace_id);
    println!("{}", invite);
    Ok(())
}

// ---------------------------------------------------------------------------
// `connect`
// ---------------------------------------------------------------------------

async fn cmd_connect(
    db_path: &std::path::Path,
    invite: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let db = DbHandle::open(db_path)?;
    let cmd = Command::EstablishConnection {
        invite_blob: invite.to_string(),
    };
    println!("topo: submitting EstablishConnection");
    let outcome = api::run(&db, cmd, COMMAND_DEADLINE).await?;
    report_outcome("connection", &outcome)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// `tenant *`
// ---------------------------------------------------------------------------

async fn cmd_tenant(
    db_path: &std::path::Path,
    socket_override: Option<&str>,
    action: Option<TenantAction>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let action = action.unwrap_or(TenantAction::List);
    let socket = resolve_socket(db_path, socket_override);
    match action {
        TenantAction::Active => {
            let resp = rpc_call(&socket, RpcMethod::ActiveTenant)
                .map_err(|e| format!("rpc: {}", e))?;
            if !resp.ok {
                return Err(resp.error.unwrap_or_else(|| "rpc error".into()).into());
            }
            let data = resp.data.unwrap_or(serde_json::Value::Null);
            match data["peer_id"].as_str() {
                Some(pid) => println!("{}", pid),
                None => println!("(no active tenant)"),
            }
            Ok(())
        }
        TenantAction::List => {
            let resp = rpc_call(&socket, RpcMethod::Tenants)
                .map_err(|e| format!("rpc: {}", e))?;
            if !resp.ok {
                return Err(resp.error.unwrap_or_else(|| "rpc error".into()).into());
            }
            let data = resp.data.unwrap_or(serde_json::Value::Null);
            println!("TENANTS ({}):", db_path.display());
            if let Some(items) = data.as_array() {
                if items.is_empty() {
                    println!("  (none)");
                } else {
                    for item in items {
                        let idx = item["index"].as_u64().unwrap_or(0);
                        let active = item["active"].as_bool().unwrap_or(false);
                        let username = item["username"].as_str().unwrap_or("");
                        let ws_name = item["workspace_name"].as_str().unwrap_or("");
                        let marker = if active { "*" } else { " " };
                        println!(
                            "  {}. {} {}@{}",
                            idx,
                            marker,
                            if username.is_empty() {
                                "(no username)"
                            } else {
                                username
                            },
                            if ws_name.is_empty() { "?" } else { ws_name },
                        );
                    }
                }
            }
            Ok(())
        }
        TenantAction::Use { index } => {
            let resp = rpc_call(&socket, RpcMethod::UseTenant { index })
                .map_err(|e| format!("rpc: {}", e))?;
            if !resp.ok {
                return Err(resp.error.unwrap_or_else(|| "rpc error".into()).into());
            }
            println!("Switched to tenant #{}", index);
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// `assert-now` / `assert-eventually`
// ---------------------------------------------------------------------------

async fn cmd_assert_now(
    db_path: &std::path::Path,
    socket_override: Option<&str>,
    predicate: &str,
    workspace: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket = resolve_socket(db_path, socket_override);
    let resp = rpc_call(
        &socket,
        RpcMethod::AssertNow {
            predicate: predicate.to_string(),
            workspace_id: workspace.map(|s| s.to_string()),
        },
    )
    .map_err(|e| format!("rpc: {}", e))?;
    if !resp.ok {
        return Err(resp.error.unwrap_or_else(|| "rpc error".into()).into());
    }
    let data = resp.data.unwrap_or(serde_json::Value::Null);
    let pass = data["pass"].as_bool().unwrap_or(false);
    println!("{}", serde_json::to_string(&data).unwrap_or_default());
    if pass {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

async fn cmd_assert_eventually(
    db_path: &std::path::Path,
    socket_override: Option<&str>,
    predicate: &str,
    timeout_ms: u64,
    interval_ms: u64,
    workspace: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket = resolve_socket(db_path, socket_override);
    let resp = rpc_call(
        &socket,
        RpcMethod::AssertEventually {
            predicate: predicate.to_string(),
            timeout_ms,
            interval_ms,
            workspace_id: workspace.map(|s| s.to_string()),
        },
    )
    .map_err(|e| format!("rpc: {}", e))?;
    if !resp.ok {
        return Err(resp.error.unwrap_or_else(|| "rpc error".into()).into());
    }
    let data = resp.data.unwrap_or(serde_json::Value::Null);
    let pass = data["pass"].as_bool().unwrap_or(false);
    println!("{}", serde_json::to_string(&data).unwrap_or_default());
    if pass {
        Ok(())
    } else {
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------
// `rpc-call`
// ---------------------------------------------------------------------------

async fn cmd_rpc_call(
    db_path: &std::path::Path,
    socket_override: Option<&str>,
    method_json: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let socket = resolve_socket(db_path, socket_override);
    let method: RpcMethod = serde_json::from_str(method_json)
        .map_err(|e| format!("invalid method json: {}", e))?;
    let resp = rpc_call(&socket, method).map_err(|e| format!("rpc: {}", e))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "ok": resp.ok,
            "error": resp.error,
            "data": resp.data,
        }))
        .unwrap_or_default()
    );
    if !resp.ok {
        std::process::exit(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn resolve_socket(db_path: &std::path::Path, override_path: Option<&str>) -> PathBuf {
    override_path
        .map(PathBuf::from)
        .unwrap_or_else(|| topo::service::socket_path_for_db(&db_path.to_string_lossy()))
}

fn report_outcome(
    label: &str,
    outcome: &CommandOutcome,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match outcome {
        CommandOutcome::Applied => {
            println!("topo: {} applied", label);
            Ok(())
        }
        CommandOutcome::Rejected { reason } => {
            Err(format!("{} rejected: {}", label, reason).into())
        }
        CommandOutcome::Blocked { missing_deps } => Err(format!(
            "{} blocked: {} missing deps",
            label,
            missing_deps.len()
        )
        .into()),
        CommandOutcome::TimedOut => Err(format!("{} timed out", label).into()),
    }
}

fn short_hex(id: &[u8; 32]) -> String {
    let h = hex::encode(id);
    h[..h.len().min(8)].to_string()
}

fn short_author(s: &str) -> &str {
    &s[..s.len().min(8)]
}
