//! Transport-to-dispatcher bridge.
//!
//! Plan-rework D: the bridge no longer calls `handle_inbound_bytes`
//! directly (which violated the single-writer rule). It now writes to
//! `inbound_bytes(status='pending')` + records an `inbound_observations`
//! row, then notifies the dispatcher's wake bus. The dispatcher's
//! Inbound step claims pending rows in batch and runs the chain on
//! each, all under one transaction. This keeps the dispatcher the only
//! tokio task running the inbound chain, which lets the chain's
//! transactions batch with other dispatcher work.
//!
//! Per `plan.md` lines 102-114: the substrate accepts inbound bytes from
//! TCP, runs `unwrap → admit → parse → context → project → apply` in one
//! transaction, and emits no other queue work. This bridge is the wire that
//! triggers that chain in the production runtime.

use std::sync::Arc;

use rusqlite::Connection;
use tokio::sync::{mpsc, Mutex};

use crate::runtime::control_loop::inbound_step::InboundOrigin;
use crate::runtime::control_loop::wake_bus::WakeBus;
use crate::runtime::control_loop::work_item::EndpointId;
use crate::runtime::transport_v2::{accept_loop, InboundDelivery};

/// Frame handed across the transport→bridge boundary. Carries the raw
/// length-stripped TCP payload plus origin metadata recovered from the
/// accepting socket. The accept loop in `transport_v2/tcp.rs` already
/// builds a richer `InboundBytes` work item; we project it down to this
/// minimum + origin for the chain.
#[derive(Debug, Clone)]
pub struct InboundFrame {
    pub bytes: Vec<u8>,
    pub origin: InboundOrigin,
}

impl From<InboundDelivery> for InboundFrame {
    fn from(d: InboundDelivery) -> Self {
        let item = d.work_item;
        Self {
            bytes: item.bytes,
            origin: InboundOrigin {
                remote_endpoint_id: item.remote_endpoint_id,
                ip: item.source_ip,
                port: item.source_port,
            },
        }
    }
}

/// Runtime errors raised by the bridge itself (channel drained / panic).
#[derive(Debug)]
pub enum BridgeError {
    ChannelClosed,
}

impl std::fmt::Display for BridgeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BridgeError::ChannelClosed => write!(f, "inbound channel closed"),
        }
    }
}

impl std::error::Error for BridgeError {}

/// Drain `inbound_rx` and forward each `InboundFrame` directly onto
/// the dispatcher's inbound channel. Plan-rework D: the bridge does NO
/// DB I/O — that's the dispatcher's job. The bridge is a pure channel
/// forwarder + wake-bus poker. This removes a per-frame fsync from the
/// hot path: the dispatcher's batch tx folds all inbound inserts +
/// chain runs into ONE commit per batch.
///
/// Returns `Ok(())` on clean shutdown (sender dropped), or
/// `Err(BridgeError)` if the bridge itself failed.
pub async fn run_transport_bridge(
    mut inbound_rx: mpsc::Receiver<InboundFrame>,
    inbound_tx: mpsc::Sender<InboundFrame>,
    wakes: Arc<WakeBus>,
) -> Result<(), BridgeError> {
    while let Some(frame) = inbound_rx.recv().await {
        let bytes_len = frame.bytes.len();
        // Forward to the dispatcher's inbound channel. If the channel
        // is full we apply backpressure by awaiting send(); the
        // dispatcher will catch up.
        if inbound_tx.send(frame).await.is_err() {
            // Dispatcher dropped its receiver (shutdown).
            return Ok(());
        }
        wakes.notify_inbound();
        tracing::trace!(
            target: "control_loop::transport_bridge",
            bytes = bytes_len,
            "inbound frame enqueued"
        );
    }
    Ok(())
}

/// Adapter task that bridges the transport's `mpsc::Receiver<InboundDelivery>`
/// onto the bridge's `mpsc::Sender<InboundFrame>`. Splitting the type
/// conversion into its own task keeps `run_transport_bridge` free of a
/// dependency on `transport_v2` types, so future transport replacements can
/// emit `InboundFrame` directly.
///
/// `local_endpoint_id` is stamped onto every produced `InboundFrame.origin
/// .remote_endpoint_id` slot. The chain interprets that slot as the
/// recipient endpoint for bootstrap-mode `connection.unwrap` (per the
/// convention documented in `inbound_step::handle_inbound_bytes`); the
/// transport itself doesn't know which local daemon owns the listener,
/// so we plumb it in here.
pub async fn forward_deliveries(
    mut deliveries_rx: mpsc::Receiver<InboundDelivery>,
    frames_tx: mpsc::Sender<InboundFrame>,
    local_endpoint_id: EndpointId,
) {
    while let Some(d) = deliveries_rx.recv().await {
        let mut frame: InboundFrame = d.into();
        // Overwrite the (transport-supplied None) recipient slot with
        // the daemon's local endpoint id so bootstrap-mode unwrap
        // derives the right key.
        frame.origin.remote_endpoint_id = Some(local_endpoint_id);
        if frames_tx.send(frame).await.is_err() {
            // Bridge gone; nothing to do.
            return;
        }
    }
}

/// Bundle returned from `install_transport_bridge_in_runtime`. Holding it
/// keeps the listener bound and the bridge alive; dropping its
/// `_frames_tx` will eventually drain the bridge.
pub struct InstalledTransportBridge {
    /// Local socket address the listener actually bound to (useful when the
    /// caller passed `:0` and needs to learn the chosen port).
    pub local_addr: std::net::SocketAddr,
    /// Sender side of the bridge's frame channel. Held so we can plumb
    /// non-TCP frame sources (e.g. tests) through the same chain.
    pub frames_tx: mpsc::Sender<InboundFrame>,
    /// Tokio handles for the spawned tasks. Dropped means the tasks keep
    /// running detached (intended); kept here for tests that want to await
    /// shutdown.
    pub _bridge_task: tokio::task::JoinHandle<Result<(), BridgeError>>,
    pub _forwarder_task: tokio::task::JoinHandle<()>,
}

/// Bind a `transport_v2` TCP listener at `listen_addr` and install a
/// bridge task that forwards inbound frames onto `inbound_tx` (the
/// dispatcher's inbound channel). After each forward the bridge
/// notifies `wakes.inbound`.
///
/// `local_endpoint_id` is the daemon's own `endpoint_id` — it is stamped
/// onto each forwarded `InboundFrame.origin.remote_endpoint_id` slot so
/// the chain's bootstrap-mode unwrap can derive the right AES key.
///
/// `_db` is kept in the signature for future hooks; the bridge no
/// longer touches it directly (the dispatcher is the sole DB writer
/// per plan-rework D).
pub async fn install_transport_bridge_in_runtime(
    listen_addr: std::net::SocketAddr,
    local_endpoint_id: EndpointId,
    _db: Arc<Mutex<Connection>>,
    wakes: Arc<WakeBus>,
    inbound_tx: mpsc::Sender<InboundFrame>,
) -> Result<InstalledTransportBridge, crate::runtime::transport_v2::TransportError> {
    // Channel from the TCP accept loop into the forwarder.
    let (deliveries_tx, deliveries_rx) = mpsc::channel::<InboundDelivery>(256);
    // Channel from the forwarder into the bridge (intermediate, lets
    // tests inject InboundFrame values without going through TCP).
    let (frames_tx, frames_rx) = mpsc::channel::<InboundFrame>(256);

    let local_addr = accept_loop(listen_addr, deliveries_tx).await?;

    let forwarder_task = tokio::spawn(forward_deliveries(
        deliveries_rx,
        frames_tx.clone(),
        local_endpoint_id,
    ));
    let bridge_task = tokio::spawn(run_transport_bridge(frames_rx, inbound_tx, wakes));

    Ok(InstalledTransportBridge {
        local_addr,
        frames_tx,
        _bridge_task: bridge_task,
        _forwarder_task: forwarder_task,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::control_loop::work_item::InboundBytes;

    #[tokio::test]
    async fn bridge_forwards_frames_to_dispatcher_channel() {
        // Plan-rework D: the bridge no longer writes to the DB. It
        // forwards each frame onto the dispatcher's inbound channel.
        let wakes = WakeBus::new();
        let (frames_tx, frames_rx) = mpsc::channel::<InboundFrame>(4);
        let (inbound_tx, mut inbound_rx) = mpsc::channel::<InboundFrame>(4);

        let task = tokio::spawn(run_transport_bridge(frames_rx, inbound_tx, wakes.clone()));

        frames_tx
            .send(InboundFrame {
                bytes: vec![0xFFu8; 8],
                origin: InboundOrigin::default(),
            })
            .await
            .unwrap();

        let received = tokio::time::timeout(std::time::Duration::from_secs(2), inbound_rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received.bytes, vec![0xFFu8; 8]);

        drop(frames_tx);
        let res = tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        res.unwrap();
    }

    #[test]
    fn delivery_to_frame_carries_origin() {
        let item = InboundBytes {
            wire_id: [9u8; 32],
            bytes: vec![1, 2, 3],
            remote_endpoint_id: Some([5u8; 32]),
            source_ip: Some("127.0.0.1".to_string()),
            source_port: Some(4242),
            received_at_ms: 7,
        };
        let d = InboundDelivery { work_item: item };
        let f: InboundFrame = d.into();
        assert_eq!(f.bytes, vec![1, 2, 3]);
        assert_eq!(f.origin.remote_endpoint_id, Some([5u8; 32]));
        assert_eq!(f.origin.ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(f.origin.port, Some(4242));
    }
}
