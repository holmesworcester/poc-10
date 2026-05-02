//! # Control-loop Runtime
//!
//! ## Purpose
//! Owner that boots the new substrate. Per plan-rework D the runtime
//! now spawns ONE dispatcher task that owns the SQLite connection and
//! round-robins across the four queue kinds (Inbound → ReadyEvents →
//! Outbox → Jobs). The dispatcher is the only writer to the queue
//! surfaces. The transport bridge writes inbound bytes to
//! `inbound_bytes(status='pending')` and notifies the wake bus; the
//! dispatcher drains. Per-connection sender actors wake on the
//! dispatcher's outbox step and drain to the socket on their own DB
//! connections.
//!
//! ## Ownership / non-ownership
//! Owns:
//! - the SQLite connection lifecycle (one for the dispatcher, one for
//!   the transport bridge's short inbound writes; per-actor connections
//!   open lazily in the sender actors),
//! - schema materialization (`ensure_infra_schema`) and crash recovery
//!   (`recover_on_startup`) at boot,
//! - default handler registration on a `ModuleRegistry` (kept for the
//!   OutboxWake dispatcher path used by tests),
//! - `OutboxWakeContext` install (with `local_endpoint_id`,
//!   [`SocketCache`], [`AddressBook`], runtime handle),
//! - the transport bridge install (writes inbound rows + notifies),
//! - the dispatcher task and a `oneshot` shutdown channel.
//!
//! Does NOT own:
//! - any sync, gossip, or peering policy (`runtime/peering`),
//! - the per-event-type projectors (`event_modules/*`),
//! - daemon main wiring (`runtime/control`) — Phase 1 only provides the
//!   owner; daemon::start will call it in a later cutover step.
//!
//! ## Interfaces
//! - [`ControlLoopRuntime::start`] — open DB, materialize schema, recover,
//!   register default handlers, install OutboxWakeContext + bridge,
//!   spawn the dispatcher.
//! - [`ControlLoopRuntime::shutdown`] — signal shutdown, await the
//!   dispatcher, drop the bridge bundle.

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use rusqlite::Connection;
use tokio::sync::{mpsc, oneshot};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

use crate::runtime::control_loop::default_handlers::{
    register_default_handlers, OutboxWakeContext,
};
use crate::runtime::control_loop::dispatcher::ModuleRegistry;
use crate::runtime::control_loop::dispatcher_loop::run_dispatcher;
use crate::runtime::control_loop::transport_bridge::{
    install_transport_bridge_in_runtime, InboundFrame, InstalledTransportBridge,
};
use crate::runtime::control_loop::wake_bus::WakeBus;
use crate::runtime::control_loop::work_item::EndpointId;
use crate::runtime::transport_v2::{AddressBook, SocketCache, TransportError};
use crate::state::db::ensure_infra_schema;
use crate::state::startup_recovery::recover_on_startup;

use std::net::SocketAddr;

/// Errors raised during runtime start/shutdown.
#[derive(Debug)]
pub enum RuntimeError {
    /// Failed to open / pragma the SQLite connection.
    Db(rusqlite::Error),
    /// Schema materialization or startup recovery failed.
    Schema(rusqlite::Error),
    /// Transport bridge install (bind / accept_loop / channels) failed.
    Transport(TransportError),
    /// I/O error during open / setup.
    Io(std::io::Error),
}

impl std::fmt::Display for RuntimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RuntimeError::Db(e) => write!(f, "open db: {}", e),
            RuntimeError::Schema(e) => write!(f, "schema/recovery: {}", e),
            RuntimeError::Transport(e) => write!(f, "transport bridge: {}", e),
            RuntimeError::Io(e) => write!(f, "io: {}", e),
        }
    }
}

impl std::error::Error for RuntimeError {}

impl From<TransportError> for RuntimeError {
    fn from(e: TransportError) -> Self {
        RuntimeError::Transport(e)
    }
}

/// Public bundle: the long-lived state of a started runtime owner. The
/// daemon holds this until shutdown.
pub struct ControlLoopRuntime {
    /// Daemon's local endpoint id (Ed25519 pubkey).
    pub local_endpoint_id: EndpointId,
    /// The address the listener actually bound to (resolved after `:0`).
    pub listen_addr: SocketAddr,
    /// SQLite connection shared between the bridge and external callers
    /// (tests and seeders). The dispatcher owns its OWN connection
    /// internally; this handle is for everyone else.
    pub db: Arc<Mutex<Connection>>,
}

/// Opaque handle bundle returned from [`ControlLoopRuntime::start`]. The
/// caller keeps this alive for the lifetime of the runtime, then passes
/// it to [`ControlLoopRuntime::shutdown`] for clean teardown.
pub struct ControlLoopHandles {
    /// The runtime owner state.
    pub runtime: ControlLoopRuntime,
    /// The installed transport bridge (listener + forwarder + bridge
    /// task). Held so the listener stays bound.
    pub transport_bridge: InstalledTransportBridge,
    /// Background dispatcher task. Joined on shutdown.
    pub workers: Vec<JoinHandle<()>>,
    /// Oneshot used to signal shutdown to the dispatcher.
    pub shutdown_tx: oneshot::Sender<()>,
    /// Wake bus shared with the bridge (and any future wake producer).
    pub wakes: Arc<WakeBus>,
    /// DB path (for sender actors to open per-connection handles).
    pub db_path: PathBuf,
}

impl ControlLoopRuntime {
    /// Start the new substrate runtime owner.
    pub async fn start(
        listen_addr: SocketAddr,
        local_endpoint_id: EndpointId,
        db_path: &Path,
    ) -> Result<ControlLoopHandles, RuntimeError> {
        // 1. Open + pragmas.
        let conn = crate::state::db::open_connection(db_path).map_err(RuntimeError::Db)?;

        // 2. Schema.
        ensure_infra_schema(&conn).map_err(RuntimeError::Schema)?;

        // 3. Recovery.
        let _report = recover_on_startup(&conn).map_err(RuntimeError::Schema)?;

        // 3b. Register periodic event-module jobs. Each event module
        //     that wants its own JobTick cadence calls `ensure_schedule`
        //     here. The kernel doesn't own job names or cadence — it
        //     just runs the named job's body when its schedule fires
        //     (see `dispatcher_loop::run_job_body`).
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        crate::event_modules::sync::job::ensure_schedule(&conn, now)
            .map_err(RuntimeError::Schema)?;

        let db = Arc::new(Mutex::new(conn));

        // 4. Default handlers (kept for OutboxWake dispatcher tests).
        let mut reg = ModuleRegistry::new();
        register_default_handlers(&mut reg);
        let _registry = Arc::new(reg);

        // 5. OutboxWakeContext install (process-wide OnceLock). If a
        //    context was already installed by a previous runtime in
        //    this process, REUSE its socket_cache + address_book so
        //    the dispatcher's sender actors see the same routing
        //    state. Otherwise build a fresh one.
        //
        //    (This matters for tests that stand up two runtimes in
        //    one process — both must agree on the `endpoint_id ->
        //    SocketAddr` map regardless of which one won the OnceLock
        //    install race.)
        let runtime_handle = tokio::runtime::Handle::try_current().ok();
        let (socket_cache, address_book) = if let Some(existing) =
            OutboxWakeContext::current()
        {
            (existing.socket_cache.clone(), existing.address_book.clone())
        } else {
            let socket_cache = Arc::new(SocketCache::new());
            let address_book = Arc::new(AddressBook::new());
            let ctx = Arc::new(OutboxWakeContext {
                local_endpoint_id,
                socket_cache: socket_cache.clone(),
                address_book: address_book.clone(),
                runtime_handle,
            });
            let _ = ctx.install();
            (socket_cache, address_book)
        };

        // 6. Wake bus.
        let wakes = WakeBus::new();

        // 7. Inbound channel between the bridge and the dispatcher.
        //    Cap is generous; backpressure flows back to the
        //    transport's accept loop if the dispatcher falls behind.
        let (inbound_tx, inbound_rx) = mpsc::channel::<InboundFrame>(2048);

        // 8. Transport bridge install. The bridge sends each
        //    `InboundFrame` on the inbound channel and notifies the
        //    wake bus.
        let transport_bridge = install_transport_bridge_in_runtime(
            listen_addr,
            local_endpoint_id,
            db.clone(),
            wakes.clone(),
            inbound_tx,
        )
        .await
        .map_err(RuntimeError::Transport)?;
        let bound_addr = transport_bridge.local_addr;

        // 9. Spawn the dispatcher with its own SQLite connection. This
        //    is the single writer for all four queue kinds.
        let dispatcher_conn =
            crate::state::db::open_connection(db_path).map_err(RuntimeError::Db)?;

        let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
        let dispatcher_db_path: PathBuf = db_path.to_path_buf();
        let dispatcher_handle = tokio::spawn(run_dispatcher(
            dispatcher_conn,
            wakes.clone(),
            local_endpoint_id,
            socket_cache.clone(),
            address_book.clone(),
            dispatcher_db_path.clone(),
            inbound_rx,
            shutdown_rx,
        ));

        let runtime = ControlLoopRuntime {
            local_endpoint_id,
            listen_addr: bound_addr,
            db,
        };

        Ok(ControlLoopHandles {
            runtime,
            transport_bridge,
            workers: vec![dispatcher_handle],
            shutdown_tx,
            wakes,
            db_path: dispatcher_db_path,
        })
    }

    /// Signal shutdown to the dispatcher, await its task, and drop the
    /// transport bridge bundle.
    pub async fn shutdown(handles: ControlLoopHandles) -> Result<(), RuntimeError> {
        let _ = handles.shutdown_tx.send(());
        // Nudge any wake-bus waiter so the dispatcher's idle select
        // observes the shutdown channel.
        handles.wakes.notify_all();

        for w in handles.workers {
            if let Err(e) = w.await {
                tracing::warn!(
                    target: "control_loop::runtime",
                    error = %e,
                    "worker join failed"
                );
            }
        }

        drop(handles.transport_bridge);
        Ok(())
    }
}
