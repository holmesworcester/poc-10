//! # Per-connection sender actor
//!
//! Plan-rework D: each `ConnectionSender` becomes its own tokio task with
//! its own SQLite connection (no contention with the dispatcher) and a
//! wake channel. The dispatcher's "Outbox" step ONLY identifies which
//! connections have pending outbox rows and notifies the matching sender
//! actor — it does NOT do DB writes itself, so the dispatcher remains
//! the sole queue claimer / inbound-chain runner.
//!
//! ## Drain loop
//!
//! ```text
//! loop {
//!   wake.recv().await;
//!   loop {
//!     sender.refill_if_needed(low, high)?;
//!     if hot_queue empty AND outbox empty(connection_id) { break; }
//!     drain_to_socket(...).await;
//!     if send_failed { schedule delayed re-wake; break; }
//!   }
//! }
//! ```
//!
//! On `send_failed` we spawn a tiny task that sleeps `BACKOFF_MS` then
//! re-pings the wake channel, replacing the OutboxWake/queue_writes path
//! that runtime.rs ignored. On clean drain the sender just goes back to
//! sleep until the next wake.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rusqlite::Connection;
use tokio::sync::mpsc;

use crate::runtime::control_loop::work_item::{ConnectionId, EndpointId};
use crate::runtime::jobs::sender::{lookup_remote_endpoint, ConnectionSender};
use crate::runtime::transport_v2::{AddressBook, SocketCache};

/// Refill thresholds aligned with `default_handlers` constants so the
/// behaviour matches the OutboxWake handler used by tests.
pub const ACTOR_LOW_WATER_BYTES: usize = 4 * 1024;
pub const ACTOR_HIGH_WATER_BYTES: usize = 64 * 1024;
/// Backoff after a failed drain before re-poking the wake channel.
pub const ACTOR_BACKOFF_MS: u64 = 250;

/// Per-actor wake channel. We use an `mpsc::channel(1)` because all the
/// actor cares about is "there is work" — multiple notifications during
/// a busy drain collapse into a single resume.
pub type WakeTx = mpsc::Sender<()>;
pub type WakeRx = mpsc::Receiver<()>;

/// Spawn a per-connection sender actor. Returns the wake-tx the
/// dispatcher uses to nudge it.
///
/// `db_path` is opened (with the standard pragmas + WAL) inside the
/// actor task so the connection is owned exclusively by it. The actor
/// is read-mostly on the DB (outbox SELECT, events_canonical SELECT)
/// with two short writes per drain (outbox::delete on socket-accept).
/// Per plan.md the dispatcher remains the only writer for the four
/// queue surfaces; the sender's outbox::delete is a connection-scoped
/// completion bookkeeping operation, not queue work.
///
/// Implementation: rusqlite's `Connection` is `!Sync`, so a future
/// holding `&Connection` cannot be Send-spawned on a multi-thread
/// runtime. We wrap the drain in `tokio::task::block_in_place` (which
/// detaches the worker thread) and use `Handle::block_on` for the
/// async `drain_to_socket`. This mirrors the OutboxWake handler's
/// approach in `default_handlers::drive_drain`.
pub fn spawn_sender_actor(
    connection_id: ConnectionId,
    local_endpoint_id: EndpointId,
    db_path: PathBuf,
    socket_cache: Arc<SocketCache>,
    address_book: Arc<AddressBook>,
) -> WakeTx {
    let (tx, rx) = mpsc::channel::<()>(1);
    let tx_self = tx.clone();
    tokio::spawn(async move {
        run_actor(
            connection_id,
            local_endpoint_id,
            db_path,
            rx,
            tx_self,
            socket_cache,
            address_book,
        )
        .await;
    });
    tx
}

async fn run_actor(
    connection_id: ConnectionId,
    local_endpoint_id: EndpointId,
    db_path: PathBuf,
    mut rx: WakeRx,
    tx_self: WakeTx,
    socket_cache: Arc<SocketCache>,
    address_book: Arc<AddressBook>,
) {
    // Open the per-actor connection on first use. If this fails we
    // log + exit; losing one actor doesn't poison the rest of the
    // substrate.
    let db = match crate::state::db::open_connection(&db_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                target: "control_loop::sender_actor",
                error = %e,
                "failed to open per-actor db connection; actor exiting",
            );
            return;
        }
    };
    let mut sender = ConnectionSender::new(connection_id);
    let handle = tokio::runtime::Handle::current();

    while let Some(()) = rx.recv().await {
        // Drain everything we can in one wake. The body is sync
        // (rusqlite Connection is !Sync) but contains an async send
        // that we drive via `block_in_place + Handle::block_on`. This
        // matches `default_handlers::drive_drain` and lets the actor
        // task run on the multi-thread runtime.
        let drain_outcome: DrainOutcome = tokio::task::block_in_place(|| {
            drain_until_empty_or_failed(
                &mut sender,
                &db,
                connection_id,
                local_endpoint_id,
                socket_cache.as_ref(),
                address_book.as_ref(),
                &handle,
            )
        });

        if matches!(drain_outcome, DrainOutcome::SendFailed) {
            // Schedule a delayed re-wake.
            let tx = tx_self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(ACTOR_BACKOFF_MS)).await;
                let _ = tx.try_send(());
            });
        }

        // Drain the wake channel: extra wakes that piled up while we
        // were running collapse into one resume.
        while let Ok(()) = rx.try_recv() {}
    }
}

#[derive(Debug)]
enum DrainOutcome {
    Idle,
    SendFailed,
}

fn drain_until_empty_or_failed(
    sender: &mut ConnectionSender,
    db: &Connection,
    connection_id: ConnectionId,
    local_endpoint_id: EndpointId,
    socket_cache: &SocketCache,
    address_book: &AddressBook,
    handle: &tokio::runtime::Handle,
) -> DrainOutcome {
    loop {
        let remote_endpoint_id = match lookup_remote_endpoint(db, &connection_id) {
            Ok(Some(ep)) => ep,
            Ok(None) => return DrainOutcome::Idle,
            Err(e) => {
                tracing::warn!(
                    target: "control_loop::sender_actor",
                    error = %e,
                    "lookup_remote_endpoint failed",
                );
                return DrainOutcome::Idle;
            }
        };

        if let Err(e) = sender.refill_if_needed(db, ACTOR_LOW_WATER_BYTES, ACTOR_HIGH_WATER_BYTES) {
            tracing::warn!(
                target: "control_loop::sender_actor",
                error = %e,
                "refill_if_needed failed",
            );
            return DrainOutcome::Idle;
        }

        if sender.hot_queue_len() == 0 {
            return DrainOutcome::Idle;
        }

        let res = handle.block_on(sender.drain_to_socket(
            db,
            local_endpoint_id,
            remote_endpoint_id,
            socket_cache,
            address_book,
        ));
        let res = match res {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    target: "control_loop::sender_actor",
                    error = %e,
                    "drain_to_socket failed",
                );
                return DrainOutcome::Idle;
            }
        };

        if res.send_failed {
            return DrainOutcome::SendFailed;
        }

        // Round-state quiet detector: stamp last_outbound so the
        // round-driver tick knows traffic is in-flight on this
        // connection. Best-effort — failure here doesn't break the
        // sender drain.
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        let _ = crate::event_modules::sync::round_state::mark_outbound(
            db,
            &connection_id,
            now_ms,
        );

        // Successful drain — loop and try again in case more rows
        // landed in the outbox while we were sending.
    }
}
