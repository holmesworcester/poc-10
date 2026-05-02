//! RPC server: Unix domain socket listener that dispatches requests to service functions.
//!
//! Connection count is bounded by a semaphore to prevent local connection-flood
//! pressure (feedback item 2).

use std::io::Write;
use std::net::SocketAddr;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, RwLock};

use serde::Serialize;
use tokio::sync::Notify;
use tracing::{info, warn};

use crate::api::WorkspaceId;
use crate::event_modules::{message, peer_shared, reaction, user, workspace};
use crate::rpc::protocol::*;
use crate::service;

/// Runtime networking info reported by the substrate after listener bind.
/// This is a thin DTO retained for the RPC `Status` surface; the legacy
/// daemon binary that populated it is gone.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NodeRuntimeNetInfo {
    pub listen_addr: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upnp: Option<crate::runtime::upnp::UpnpMappingReport>,
}

/// Maximum concurrent RPC connections the server will handle.
/// Additional connections block until a slot is freed.
const MAX_CONCURRENT_CONNECTIONS: usize = 64;

/// Daemon-wide shared state.
///
/// Active-tenant ergonomic: `active_workspace_id` is the workspace the
/// daemon's CLI commands target by default. RAM only — set via
/// `topo tenant use <N>`, lost on restart (poc-9 plan: no durable
/// active-tenant column).
pub struct DaemonState {
    pub db_path: String,
    pub active_workspace_id: RwLock<Option<WorkspaceId>>,
    /// Runtime lifecycle state.
    pub runtime_state: RwLock<RuntimeState>,
    /// Runtime networking info (listen addr, UPnP result). Set once the
    /// QUIC endpoint is bound; UPnP result is populated while UPnP mode is enabled.
    pub runtime_net: RwLock<Option<NodeRuntimeNetInfo>>,
    /// The daemon's resolved bind address, set as soon as startup reserves the
    /// UDP socket. This survives the idle-no-tenants phase before runtime
    /// activation reports `runtime_net.listen_addr`.
    pub resolved_bind_addr: RwLock<Option<SocketAddr>>,
    /// Whether runtime-managed UPnP mode is enabled for this daemon session.
    pub upnp_enabled: RwLock<bool>,
    /// Last UPnP mapping report for the active runtime session.
    pub upnp_result: RwLock<Option<crate::runtime::upnp::UpnpMappingReport>>,
    /// Wake-up trigger for runtime state reevaluation after tenant-changing commands.
    pub runtime_recheck: Notify,
    /// Invite/link strings stored by number (index+1 = invite ref number).
    pub invite_refs: RwLock<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeState {
    IdleNoTenants,
    Active,
}

impl RuntimeState {
    pub fn as_str(self) -> &'static str {
        match self {
            RuntimeState::IdleNoTenants => "IdleNoTenants",
            RuntimeState::Active => "Active",
        }
    }
}

impl DaemonState {
    /// Create new daemon state. Active workspace is `None` until the
    /// operator selects one via `topo tenant use <N>` or auto-resolves
    /// via `require_active_workspace`.
    pub fn new(db_path: &str) -> Self {
        DaemonState {
            db_path: db_path.to_string(),
            active_workspace_id: RwLock::new(None),
            // Runtime manager owns lifecycle transitions.
            runtime_state: RwLock::new(RuntimeState::IdleNoTenants),
            runtime_net: RwLock::new(None),
            resolved_bind_addr: RwLock::new(None),
            upnp_enabled: RwLock::new(false),
            upnp_result: RwLock::new(None),
            runtime_recheck: Notify::new(),
            invite_refs: RwLock::new(Vec::new()),
        }
    }

    pub fn notify_runtime_recheck(&self) {
        self.runtime_recheck.notify_waiters();
    }

    fn runtime_listen_addr(&self) -> Option<SocketAddr> {
        self.runtime_net
            .read()
            .unwrap()
            .as_ref()
            .and_then(|info| info.listen_addr.parse::<SocketAddr>().ok())
    }

    fn effective_listen_addr(&self) -> Option<SocketAddr> {
        self.runtime_listen_addr()
            .or_else(|| *self.resolved_bind_addr.read().unwrap())
    }

    /// Resolve the active workspace_id for a request.
    ///
    /// Lookup order:
    /// 1. The request explicitly supplied a workspace_id.
    /// 2. `active_workspace_id` is set (via `topo tenant use`).
    /// 3. Exactly one workspace is hosted — auto-select it.
    /// 4. Else error.
    ///
    /// Returns the base64 workspace_id (the projection-table key form).
    pub fn require_active_workspace(
        &self,
        request_workspace_id: Option<WorkspaceId>,
    ) -> Result<String, String> {
        if let Some(ws) = request_workspace_id {
            return Ok(crate::crypto::event_id_to_base64(&ws));
        }
        if let Some(ws) = *self.active_workspace_id.read().unwrap() {
            return Ok(crate::crypto::event_id_to_base64(&ws));
        }
        // Auto-select if exactly one workspace is hosted.
        if let Ok(conn) = crate::db::open_connection(&self.db_path) {
            let _ = crate::db::schema::create_tables(&conn);
            if let Ok(bindings) = crate::db::transport_creds::list_hosted_workspaces(&conn) {
                if bindings.len() == 1 {
                    return Ok(bindings[0].workspace_id.clone());
                }
                if bindings.len() > 1 {
                    return Err(
                        "no active tenant — run `topo tenant use <N>` or pass --workspace"
                            .to_string(),
                    );
                }
            }
        }
        Err("no active tenant — create a workspace or accept an invite first".to_string())
    }

    /// Store an invite/link string and return its 1-based reference number.
    pub fn add_invite_ref(&self, link: String) -> usize {
        let mut refs = self.invite_refs.write().unwrap();
        refs.push(link);
        refs.len()
    }

    /// Resolve an invite ref: numeric string → stored link, otherwise passthrough.
    pub fn resolve_invite_ref(&self, selector: &str) -> Result<String, String> {
        if let Ok(num) = selector.parse::<usize>() {
            let refs = self.invite_refs.read().unwrap();
            if num >= 1 && num <= refs.len() {
                return Ok(refs[num - 1].clone());
            }
            return Err(format!(
                "invalid invite ref #{}; available: 1-{}",
                num,
                refs.len()
            ));
        }
        // Passthrough: treat as a raw invite link
        Ok(selector.to_string())
    }
}

/// Parse a `--workspace` CLI argument into a `WorkspaceId`. Accepts either
/// hex (64 chars) or base64 (44 chars w/ padding) encoding. Returns `None`
/// for unparseable input — the caller's `require_active_workspace` then
/// falls back to the daemon-default behavior.
fn parse_workspace_id_arg(s: &str) -> Option<WorkspaceId> {
    if s.len() == 64 {
        let bytes = hex::decode(s).ok()?;
        if bytes.len() == 32 {
            let mut id = [0u8; 32];
            id.copy_from_slice(&bytes);
            return Some(id);
        }
    }
    crate::crypto::event_id_from_base64(s)
}

/// Helper: resolve the active workspace_id (request-provided or daemon
/// default), open the daemon DB, and pass `(workspace_id_b64, db)` to the
/// closure. Returns the closure's `RpcResponse` on success, or an error
/// response if no workspace is selectable or the DB cannot be opened.
fn with_active_workspace_db<F>(
    state: &DaemonState,
    request_workspace_id: Option<WorkspaceId>,
    f: F,
) -> RpcResponse
where
    F: FnOnce(&str, &rusqlite::Connection) -> RpcResponse,
{
    match state.require_active_workspace(request_workspace_id) {
        Ok(ws_b64) => match service::open_db(&state.db_path) {
            Ok(db) => f(&ws_b64, &db),
            Err(e) => RpcResponse::error(e.to_string()),
        },
        Err(e) => RpcResponse::error(e),
    }
}

/// Tenant info returned by the Tenants command.
#[derive(Debug, Serialize)]
struct TenantItem {
    index: usize,
    peer_id: String,
    username: String,
    workspace_id: String,
    workspace_name: String,
    active: bool,
}

/// Run the RPC server on a Unix socket, dispatching to service functions.
/// Blocks the calling thread. Intended to be run in a background thread.
pub fn run_rpc_server(
    socket_path: &Path,
    state: Arc<DaemonState>,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    shutdown_notify: Arc<tokio::sync::Notify>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Remove stale socket file if it exists.
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }

    // Ensure parent directory exists.
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(socket_path)?;
    // Set non-blocking so we can check the shutdown flag periodically.
    listener.set_nonblocking(true)?;

    info!("RPC server listening on {}", socket_path.display());

    // Bounded connection counter (poor-man's semaphore without extra deps).
    let active = Arc::new(AtomicUsize::new(0));

    while !shutdown.load(std::sync::atomic::Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _addr)) => {
                let current = active.load(AtomicOrdering::Relaxed);
                if current >= MAX_CONCURRENT_CONNECTIONS {
                    warn!(
                        "RPC connection limit reached ({}), rejecting",
                        MAX_CONCURRENT_CONNECTIONS
                    );
                    // Drop `stream` immediately — client gets connection-reset.
                    drop(stream);
                    continue;
                }

                let st = state.clone();
                let active_clone = active.clone();
                let shutdown_clone = shutdown.clone();
                let notify_clone = shutdown_notify.clone();
                active.fetch_add(1, AtomicOrdering::Relaxed);

                std::thread::spawn(move || {
                    if let Err(e) = handle_connection(stream, &st, &shutdown_clone, &notify_clone) {
                        warn!("RPC connection error: {}", e);
                    }
                    active_clone.fetch_sub(1, AtomicOrdering::Relaxed);
                });
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                // No pending connections — sleep briefly and check shutdown.
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(e) => {
                warn!("RPC accept error: {}", e);
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }

    // Cleanup socket file.
    let _ = std::fs::remove_file(socket_path);
    info!("RPC server shut down");
    Ok(())
}

fn handle_connection(
    mut stream: std::os::unix::net::UnixStream,
    state: &DaemonState,
    shutdown: &std::sync::atomic::AtomicBool,
    shutdown_notify: &tokio::sync::Notify,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Set blocking for this connection.
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(std::time::Duration::from_secs(30)))?;
    stream.set_write_timeout(Some(std::time::Duration::from_secs(30)))?;

    let req: RpcRequest = decode_frame(&mut stream)?;

    if req.version != PROTOCOL_VERSION {
        let resp = RpcResponse::error(format!(
            "version mismatch: server={}, client={}",
            PROTOCOL_VERSION, req.version
        ));
        let frame = encode_frame(&resp)?;
        stream.write_all(&frame)?;
        return Ok(());
    }

    let resp = dispatch(state, req.method, shutdown, shutdown_notify);
    let frame = encode_frame(&resp)?;
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}

fn upnp_response_data(
    enabled: bool,
    report: Option<&crate::runtime::upnp::UpnpMappingReport>,
    fallback_error: &str,
) -> serde_json::Value {
    let mut data = serde_json::Map::new();
    data.insert("enabled".into(), serde_json::Value::Bool(enabled));
    if let Some(report) = report {
        if let Ok(serde_json::Value::Object(fields)) = serde_json::to_value(report) {
            for (key, value) in fields {
                data.insert(key, value);
            }
        }
    } else {
        data.insert("status".into(), serde_json::json!("not_attempted"));
        data.insert("error".into(), serde_json::json!(fallback_error));
    }
    serde_json::Value::Object(data)
}

fn dispatch(
    state: &DaemonState,
    method: RpcMethod,
    shutdown: &std::sync::atomic::AtomicBool,
    shutdown_notify: &tokio::sync::Notify,
) -> RpcResponse {
    let db_path = &state.db_path;

    match method {
        RpcMethod::Shutdown => {
            shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
            shutdown_notify.notify_waiters();
            RpcResponse::success(serde_json::json!({"shutdown": true}))
        }

        // ----- Tenant management (daemon state) -----
        // poc-9: tenants are workspaces this daemon hosts. The "active
        // tenant" is the workspace_id whose ergonomics CLI commands
        // default to; it lives in `state.active_workspace_id` (RAM only,
        // lost on restart).
        RpcMethod::Tenants => match crate::db::open_connection(db_path) {
            Ok(conn) => {
                let _ = crate::db::schema::create_tables(&conn);
                let active_ws = state
                    .active_workspace_id
                    .read()
                    .unwrap()
                    .map(|w| crate::crypto::event_id_to_base64(&w))
                    .unwrap_or_default();
                match workspace::list_tenants_for_display(&conn, &active_ws) {
                    Ok(tenants) => {
                        let items: Vec<TenantItem> = tenants
                            .into_iter()
                            .enumerate()
                            .map(|(i, tenant)| TenantItem {
                                index: i + 1,
                                peer_id: tenant.peer_id,
                                username: tenant.username,
                                workspace_id: tenant.workspace_id,
                                workspace_name: tenant.workspace_name,
                                active: tenant.active,
                            })
                            .collect();
                        RpcResponse::success(serde_json::json!(items))
                    }
                    Err(e) => RpcResponse::error(e.to_string()),
                }
            }
            Err(e) => RpcResponse::error(e.to_string()),
        },

        RpcMethod::UseTenant { index } => match crate::db::open_connection(db_path) {
            Ok(conn) => {
                let _ = crate::db::schema::create_tables(&conn);
                match crate::api::list_workspaces_blocking(&conn) {
                    Ok(workspaces) => {
                        if index == 0 || index > workspaces.len() {
                            return RpcResponse::error(format!(
                                "invalid tenant number {}; available: 1-{}",
                                index,
                                workspaces.len()
                            ));
                        }
                        let entry = &workspaces[index - 1];
                        *state.active_workspace_id.write().unwrap() = Some(entry.id);
                        RpcResponse::success(serde_json::json!({
                            "workspace_id": crate::crypto::event_id_to_base64(&entry.id),
                            "workspace_name": entry.name,
                        }))
                    }
                    Err(e) => RpcResponse::error(e.to_string()),
                }
            }
            Err(e) => RpcResponse::error(e.to_string()),
        },

        RpcMethod::ActiveTenant => {
            let active = *state.active_workspace_id.read().unwrap();
            match active {
                Some(ws) => RpcResponse::success(serde_json::json!({
                    "workspace_id": crate::crypto::event_id_to_base64(&ws),
                })),
                None => RpcResponse::success(serde_json::json!({"workspace_id": null})),
            }
        }

        // Authoring commands are routed through `api::run(Command::*)` by
        // the CLI binary. The legacy `recorded_by`-based authoring path was
        // retired; the daemon RPC surface preserves the method names so
        // older clients fail loudly instead of crashing.
        RpcMethod::CreateWorkspace { .. }
        | RpcMethod::Send { .. }
        | RpcMethod::Generate { .. }
        | RpcMethod::React { .. }
        | RpcMethod::DeleteMessage { .. } => RpcResponse::error(
            "authoring is not implemented on the substrate-only daemon RPC surface; use `api::run`"
                .to_string(),
        ),

        // ----- Read-only commands (call event modules directly) -----
        RpcMethod::TransportKeys => match crate::db::open_connection(db_path) {
            Ok(db) => {
                if let Err(e) = crate::db::schema::create_tables(&db) {
                    return RpcResponse::error(e.to_string());
                }
                match crate::state::db::transport_creds::list_local_peers_with_source(&db) {
                    Ok(keys) => RpcResponse::success(serde_json::json!(keys)),
                    Err(e) => RpcResponse::error(e.to_string()),
                }
            }
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::TransportAuth => RpcResponse::error(
            "transport-auth is not implemented on the substrate-only daemon".to_string(),
        ),
        RpcMethod::Messages { limit, workspace_id } => {
            let req_ws = workspace_id.as_deref().and_then(parse_workspace_id_arg);
            with_active_workspace_db(state, req_ws, |ws, db| match message::list(db, ws, limit) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            })
        }
        RpcMethod::Status => {
            let with_runtime_state = |data: workspace::StatusResponse| {
                let mut json = serde_json::to_value(data).unwrap_or(serde_json::Value::Null);
                json["daemon_db_path"] = serde_json::json!(db_path);
                json["runtime_state"] =
                    serde_json::json!(state.runtime_state.read().unwrap().as_str());
                if let Some(net_info) = state.runtime_net.read().unwrap().as_ref() {
                    if let Ok(net_val) = serde_json::to_value(net_info) {
                        json["runtime"] = net_val;
                    }
                }
                let upnp_enabled = *state.upnp_enabled.read().unwrap();
                // When the runtime isn't active, synthesize a minimal "runtime"
                // block from early-bound listen addr and UPnP mode state so that
                // `topo status` always shows networking info.
                if json.get("runtime").is_none() {
                    let resolved_bind = state.resolved_bind_addr.read().unwrap();
                    let upnp = state.upnp_result.read().unwrap();
                    if resolved_bind.is_some() || upnp.is_some() || upnp_enabled {
                        let mut rt = serde_json::Map::new();
                        if let Some(addr) = *resolved_bind {
                            rt.insert(
                                "listen_addr".into(),
                                serde_json::Value::String(addr.to_string()),
                            );
                        }
                        rt.insert("upnp_enabled".into(), serde_json::Value::Bool(upnp_enabled));
                        if let Some(ref report) = *upnp {
                            if let Ok(v) = serde_json::to_value(report) {
                                rt.insert("upnp".into(), v);
                            }
                        }
                        json["runtime"] = serde_json::Value::Object(rt);
                    }
                } else if let Some(rt) = json.get_mut("runtime") {
                    rt["upnp_enabled"] = serde_json::Value::Bool(upnp_enabled);
                    // Runtime is active but UPnP might only be in daemon-level state
                    // (e.g. while a refresh task is still writing the latest report).
                    // Only inject if the port matches the current listen address.
                    if rt.get("upnp").is_none() {
                        if let Some(ref report) = *state.upnp_result.read().unwrap() {
                            let port_matches = rt["listen_addr"]
                                .as_str()
                                .and_then(|a| a.parse::<std::net::SocketAddr>().ok())
                                .map(|a| a.port() == report.requested_external_port)
                                .unwrap_or(false);
                            if port_matches {
                                if let Ok(v) = serde_json::to_value(report) {
                                    rt["upnp"] = v;
                                }
                            }
                        }
                    }
                }
                RpcResponse {
                    version: crate::rpc::protocol::PROTOCOL_VERSION,
                    ok: true,
                    error: None,
                    data: Some(json),
                }
            };

            match state.require_active_workspace(None) {
                Ok(ws) => match service::open_db(db_path) {
                    Ok(db) => {
                        let data = workspace::status(&db, &ws);
                        with_runtime_state(data)
                    }
                    Err(e) => RpcResponse::error(e.to_string()),
                },
                Err(no_active_err) => match crate::db::open_connection(db_path) {
                    Ok(db) => {
                        let _ = crate::db::schema::create_tables(&db);
                        let tenant_count: i64 = crate::db::transport_creds::list_hosted_workspaces(
                            &db,
                        )
                        .map(|b| b.len() as i64)
                        .unwrap_or(0);
                        if tenant_count > 1 {
                            RpcResponse::error(no_active_err)
                        } else {
                            // Empty/pre-identity or single-tenant: status
                            // with zeroed counters so health probes work.
                            let data = workspace::status(&db, "");
                            with_runtime_state(data)
                        }
                    }
                    Err(e) => RpcResponse::error(e.to_string()),
                },
            }
        }
        RpcMethod::AssertNow {
            predicate,
            workspace_id,
        } => {
            let req_ws = workspace_id.as_deref().and_then(parse_workspace_id_arg);
            let parsed = match crate::assert::parse_predicate(&predicate) {
                Ok(p) => p,
                Err(e) => return RpcResponse::error(e),
            };
            let (field, op, expected) = parsed;
            let needs_ws = !crate::assert::is_substrate_field(&field);
            let ws_b64 = if needs_ws {
                match state.require_active_workspace(req_ws) {
                    Ok(s) => Some(s),
                    Err(e) => return RpcResponse::error(e),
                }
            } else {
                None
            };
            match service::open_db(db_path) {
                Ok(db) => match crate::assert::query_field(&db, &field, ws_b64.as_deref()) {
                    Ok(actual) => RpcResponse::success(crate::assert::AssertResponse {
                        pass: op.eval(actual, expected),
                        field,
                        actual,
                        op: op.symbol().to_string(),
                        expected,
                        timed_out: false,
                        debug: None,
                    }),
                    Err(e) => RpcResponse::error(e),
                },
                Err(e) => RpcResponse::error(e.to_string()),
            }
        }
        RpcMethod::AssertEventually {
            predicate,
            timeout_ms,
            interval_ms,
            workspace_id,
        } => {
            let req_ws = workspace_id.as_deref().and_then(parse_workspace_id_arg);
            // Decide if we need a workspace scope before entering the polling
            // loop (parse the predicate field once).
            let needs_ws = match crate::assert::parse_predicate(&predicate) {
                Ok((field, _, _)) => !crate::assert::is_substrate_field(&field),
                Err(_) => true,
            };
            let ws_b64: Option<String> = if needs_ws {
                match state.require_active_workspace(req_ws) {
                    Ok(s) => Some(s),
                    Err(e) => return RpcResponse::error(e),
                }
            } else {
                None
            };
            match crate::assert::assert_eventually(
                db_path,
                ws_b64.as_deref(),
                &predicate,
                timeout_ms,
                interval_ms,
            ) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            }
        }
        RpcMethod::Reactions => with_active_workspace_db(state, None, |ws, db| {
            match reaction::list(db, ws) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            }
        }),
        RpcMethod::Users { workspace_id } => {
            let req_ws = workspace_id.as_deref().and_then(parse_workspace_id_arg);
            with_active_workspace_db(state, req_ws, |ws, db| match user::list_items(db, ws) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            })
        }
        RpcMethod::Keys { summary } => with_active_workspace_db(state, None, |ws, db| {
            match workspace::keys(db, ws, summary) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            }
        }),
        RpcMethod::ContentKeys { summary } => with_active_workspace_db(
            state,
            None,
            |ws, db| match workspace::content_keys(db, ws, summary) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            },
        ),
        RpcMethod::Peers { workspace_id } => {
            let req_ws = workspace_id.as_deref().and_then(parse_workspace_id_arg);
            with_active_workspace_db(state, req_ws, |ws, db| {
                match peer_shared::list_peers(db, ws) {
                    Ok(data) => RpcResponse::success(data),
                    Err(e) => RpcResponse::error(e.to_string()),
                }
            })
        }
        RpcMethod::Workspaces => match crate::db::open_connection(db_path) {
            Ok(db) => {
                let _ = crate::db::schema::create_tables(&db);
                match workspace::list_all_items(&db) {
                    Ok(data) => RpcResponse::success(data),
                    Err(e) => RpcResponse::error(e.to_string()),
                }
            }
            Err(e) => RpcResponse::error(e.to_string()),
        },
        RpcMethod::IntroAttempts { .. }
        | RpcMethod::CreateInvite { .. }
        | RpcMethod::RotateKey => RpcResponse::error(
            "this command is not implemented on the substrate-only daemon".to_string(),
        ),
        RpcMethod::Upnp { action } => match action {
            UpnpAction::Disable => {
                *state.upnp_enabled.write().unwrap() = false;
                *state.upnp_result.write().unwrap() = None;
                if let Some(ref mut info) = *state.runtime_net.write().unwrap() {
                    info.upnp = None;
                }
                RpcResponse::success(upnp_response_data(false, None, "disabled"))
            }
            UpnpAction::Status => {
                let enabled = *state.upnp_enabled.read().unwrap();
                let report = state.upnp_result.read().unwrap().clone();
                let fallback = if enabled {
                    "runtime not active yet; mapping will be attempted when runtime starts"
                } else {
                    "disabled"
                };
                RpcResponse::success(upnp_response_data(enabled, report.as_ref(), fallback))
            }
            UpnpAction::Enable => {
                *state.upnp_enabled.write().unwrap() = true;
                let listen_addr = match state.runtime_net.read().unwrap().as_ref() {
                    Some(info) => match info.listen_addr.parse::<std::net::SocketAddr>() {
                        Ok(addr) => Some(addr),
                        Err(e) => {
                            return RpcResponse::error(format!("invalid listen addr: {}", e));
                        }
                    },
                    None => None,
                };
                let Some(listen_addr) = listen_addr else {
                    *state.upnp_result.write().unwrap() = None;
                    return RpcResponse::success(upnp_response_data(
                        true,
                        None,
                        "runtime not active yet; mapping will be attempted when runtime starts",
                    ));
                };
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => return RpcResponse::error(format!("failed to start runtime: {}", e)),
                };
                let report = rt.block_on(crate::runtime::upnp::attempt_udp_port_mapping(
                    listen_addr,
                    std::time::Duration::from_secs(10),
                ));
                *state.upnp_result.write().unwrap() = Some(report.clone());
                if let Some(ref mut ni) = *state.runtime_net.write().unwrap() {
                    let runtime_port = ni
                        .listen_addr
                        .parse::<std::net::SocketAddr>()
                        .map(|a| a.port())
                        .unwrap_or(0);
                    if runtime_port == listen_addr.port() {
                        ni.upnp = Some(report.clone());
                    }
                }
                RpcResponse::success(upnp_response_data(true, Some(&report), "enabled"))
            }
        },
        RpcMethod::CreateDeviceLink { .. }
        | RpcMethod::AcceptLink { .. }
        | RpcMethod::Identity
        | RpcMethod::AcceptInvite { .. } => RpcResponse::error(
            "this command is not implemented on the substrate-only daemon".to_string(),
        ),
        RpcMethod::View { limit } => match state.require_active_workspace(None) {
            Ok(ws) => match workspace::view_for_workspace(db_path, &ws, limit) {
                Ok(data) => RpcResponse::success(data),
                Err(e) => RpcResponse::error(e.to_string()),
            },
            Err(e) => RpcResponse::error(e),
        },

        RpcMethod::Forward { action } => {
            use crate::state::live_hints;
            match action {
                ForwardAction::Enable => {
                    live_hints::set_forward_on_have(true);
                    RpcResponse::success(serde_json::json!({ "forward_on_have": true }))
                }
                ForwardAction::Disable => {
                    live_hints::set_forward_on_have(false);
                    RpcResponse::success(serde_json::json!({ "forward_on_have": false }))
                }
                ForwardAction::Status => {
                    let enabled = live_hints::forward_on_have_enabled();
                    RpcResponse::success(serde_json::json!({ "forward_on_have": enabled }))
                }
            }
        }

        RpcMethod::EventBlocked => match service::open_db(db_path) {
            Ok(db) => {
                // The legacy `blocked_event_deps` table is keyed by
                // `peer_id`; that field is gone in poc-9. The substrate
                // tracks blocked-by edges in `blocked_by_event` instead.
                // Return an empty list rather than fabricating peer_id
                // joins that don't exist.
                let _ = db;
                RpcResponse::success(serde_json::json!(Vec::<serde_json::Value>::new()))
            }
            Err(e) => RpcResponse::error(e.to_string()),
        },

        RpcMethod::EventTimeline { event_id } => match service::open_db(db_path) {
            Ok(db) => {
                let tl = crate::db::timeline::EventTimeline::new(&db);
                match tl.load(&event_id) {
                    Ok(Some(row)) => RpcResponse::success(serde_json::json!({
                        "event_id": row.event_id,
                        "first_received_at_ms": row.first_received_at,
                        "first_stored_at_ms": row.first_stored_at,
                        "blocked_at_ms": row.blocked_at,
                        "unblocked_at_ms": row.unblocked_at,
                        "unblocked_by_event_id": row.unblocked_by_event_id,
                        "projected_at_ms": row.projected_at,
                    })),
                    Ok(None) => {
                        RpcResponse::error(format!("no timeline entry for event {}", event_id))
                    }
                    Err(e) => RpcResponse::error(e.to_string()),
                }
            }
            Err(e) => RpcResponse::error(e.to_string()),
        },

        RpcMethod::Stats => with_active_workspace_db(state, None, |ws, db| {
            let count_ws = |sql: &str| -> i64 {
                db.query_row(sql, rusqlite::params![ws], |r| r.get(0))
                    .unwrap_or(0)
            };
            let resp = serde_json::json!({
                "message_count": message::count(db, ws).unwrap_or(0),
                "reaction_count": reaction::count(db, ws).unwrap_or(0),
                "deleted_message_count": count_ws("SELECT COUNT(*) FROM deleted_messages WHERE workspace_id = ?1"),
                "user_count": user::count(db, ws).unwrap_or(0),
                "peer_count": peer_shared::count(db, ws).unwrap_or(0),
                "admin_count": 0,
                "workspace_count": count_ws("SELECT COUNT(*) FROM workspaces WHERE workspace_id = ?1"),
                "user_invite_count": count_ws("SELECT COUNT(*) FROM user_invites WHERE workspace_id = ?1"),
                "device_invite_count": count_ws("SELECT COUNT(*) FROM device_invites WHERE workspace_id = ?1"),
                "key_secret_count": count_ws("SELECT COUNT(*) FROM key_secrets WHERE workspace_id = ?1"),
                "event_count": db.query_row("SELECT COUNT(*) FROM events", [], |r| r.get::<_, i64>(0)).unwrap_or(0),
                "recorded_event_count": 0,
                "valid_event_count": 0,
                "blocked_event_count": 0,
                "rejected_event_count": 0,
                "endpoint_observation_count": 0,
            });
            RpcResponse::success(resp)
        }),

        RpcMethod::Replay { .. }
        | RpcMethod::Connections
        | RpcMethod::Intro { .. } => RpcResponse::error(
            "this command is not implemented on the substrate-only daemon".to_string(),
        ),

        #[cfg(feature = "discovery")]
        RpcMethod::Discover { .. } => RpcResponse::error(
            "discover is not implemented on the substrate-only daemon".to_string(),
        ),

        RpcMethod::EventList
        | RpcMethod::EventListByIds { .. }
        | RpcMethod::EventShow { .. }
        | RpcMethod::EventDeps { .. } => RpcResponse::error(
            "event-list family is not implemented on the substrate-only daemon".to_string(),
        ),

        // ----- Subscription commands (retired in substrate-only daemon) -----
        RpcMethod::SubCreate { .. }
        | RpcMethod::SubList
        | RpcMethod::SubDisable { .. }
        | RpcMethod::SubEnable { .. }
        | RpcMethod::SubPoll { .. }
        | RpcMethod::SubAck { .. }
        | RpcMethod::SubState { .. } => RpcResponse::error(
            "subscriptions are not implemented in the substrate-only daemon".to_string(),
        ),
    }
}

/// Invoke the real RPC dispatch path in-process without Unix socket framing.
///
/// This is the seam used by virtual-daemon tests and simulator control code.
pub fn dispatch_rpc_method(state: &DaemonState, method: RpcMethod) -> RpcResponse {
    let shutdown = std::sync::atomic::AtomicBool::new(false);
    let shutdown_notify = tokio::sync::Notify::new();
    dispatch(state, method, &shutdown, &shutdown_notify)
}

