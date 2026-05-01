//! TCP socket cache + `[u32 length][bytes]` framing.
//!
//! `send(remote_endpoint_id, OutboundFrame)` is the only egress.
//! `accept_loop` is the only ingress: incoming bytes get pushed onto an
//! `Inbound` channel as `InboundBytes` work items.
//!
//! The transport produces and interprets no application bytes. It only does
//! length-prefixed framing.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Mutex};

use super::super::control_loop::work_item::{BlakeId, EndpointId, InboundBytes};
use super::addrs::AddressResolver;
use super::outbound_frame::OutboundFrame;

const MAX_FRAME_BYTES: u32 = 16 * 1024 * 1024; // 16 MiB hard cap

/// Errors returned by the transport layer.
#[derive(Debug)]
pub enum TransportError {
    Io(io::Error),
    UnknownAddress(EndpointId),
    FrameTooLarge(u32),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Io(e) => write!(f, "transport io: {}", e),
            TransportError::UnknownAddress(_) => write!(f, "no address for remote endpoint"),
            TransportError::FrameTooLarge(n) => write!(f, "frame too large: {} bytes", n),
        }
    }
}

impl std::error::Error for TransportError {}

impl From<io::Error> for TransportError {
    fn from(e: io::Error) -> Self {
        TransportError::Io(e)
    }
}

/// What the accept loop puts on the inbound channel: a typed `InboundBytes`
/// work item ready for the queue.
#[derive(Debug, Clone)]
pub struct InboundDelivery {
    pub work_item: InboundBytes,
}

/// Socket cache keyed by `(local_endpoint_id, remote_endpoint_id)`. Holds an
/// outgoing-direction `TcpStream` so we don't reconnect for every frame.
///
/// TODO(plan.md): per-endpoint connection pooling, idle eviction, half-open
/// detection. Phase 1 is single-stream-per-pair.
#[derive(Clone, Default)]
pub struct SocketCache {
    inner: Arc<Mutex<HashMap<(EndpointId, EndpointId), Arc<Mutex<TcpStream>>>>>,
}

impl SocketCache {
    pub fn new() -> Self {
        Self::default()
    }

    async fn get_or_dial(
        &self,
        local: EndpointId,
        remote: EndpointId,
        addr: SocketAddr,
    ) -> Result<Arc<Mutex<TcpStream>>, TransportError> {
        let key = (local, remote);
        {
            let g = self.inner.lock().await;
            if let Some(s) = g.get(&key) {
                return Ok(s.clone());
            }
        }
        let stream = TcpStream::connect(addr).await?;
        let arc = Arc::new(Mutex::new(stream));
        let mut g = self.inner.lock().await;
        // Recheck — racing dialer may have inserted in the meantime.
        if let Some(existing) = g.get(&key) {
            return Ok(existing.clone());
        }
        g.insert(key, arc.clone());
        Ok(arc)
    }

    pub async fn drop_stream(&self, local: EndpointId, remote: EndpointId) {
        let mut g = self.inner.lock().await;
        g.remove(&(local, remote));
    }
}

/// Send an already-wrapped frame to `remote_endpoint_id`. The framing is
/// `[u32 BE length][bytes]`.
pub async fn send(
    cache: &SocketCache,
    resolver: &dyn AddressResolver,
    local_endpoint_id: EndpointId,
    remote_endpoint_id: EndpointId,
    frame: OutboundFrame,
) -> Result<(), TransportError> {
    let len = frame.len();
    if len as u64 > MAX_FRAME_BYTES as u64 {
        return Err(TransportError::FrameTooLarge(len as u32));
    }
    let addr = resolver
        .resolve(&remote_endpoint_id)
        .ok_or(TransportError::UnknownAddress(remote_endpoint_id))?;
    let stream = cache
        .get_or_dial(local_endpoint_id, remote_endpoint_id, addr)
        .await?;

    let bytes = frame.into_bytes();
    let mut g = stream.lock().await;
    let prefix = (bytes.len() as u32).to_be_bytes();
    if let Err(e) = g.write_all(&prefix).await {
        // Drop the cached stream on write error so the next call redials.
        drop(g);
        cache.drop_stream(local_endpoint_id, remote_endpoint_id).await;
        return Err(TransportError::Io(e));
    }
    if let Err(e) = g.write_all(&bytes).await {
        drop(g);
        cache.drop_stream(local_endpoint_id, remote_endpoint_id).await;
        return Err(TransportError::Io(e));
    }
    Ok(())
}

/// Spawn an accept loop that listens on `listen_addr` and pushes
/// `InboundDelivery` items onto `tx`. Each accepted connection runs in its
/// own task, reading length-prefixed frames until EOF / error.
///
/// Returns the local `SocketAddr` after binding (useful when listen_addr has
/// port 0).
pub async fn accept_loop(
    listen_addr: SocketAddr,
    tx: mpsc::Sender<InboundDelivery>,
) -> Result<SocketAddr, TransportError> {
    let listener = TcpListener::bind(listen_addr).await?;
    let local = listener.local_addr()?;

    tokio::spawn(async move {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(p) => p,
                Err(e) => {
                    tracing::warn!(target: "transport_v2", error=%e, "accept failed");
                    continue;
                }
            };
            let tx_inner = tx.clone();
            tokio::spawn(async move {
                if let Err(e) = read_loop(stream, peer, tx_inner).await {
                    tracing::debug!(target: "transport_v2", error=%e, "read loop ended");
                }
            });
        }
    });

    Ok(local)
}

async fn read_loop(
    mut stream: TcpStream,
    peer: SocketAddr,
    tx: mpsc::Sender<InboundDelivery>,
) -> io::Result<()> {
    loop {
        let mut len_buf = [0u8; 4];
        if let Err(e) = stream.read_exact(&mut len_buf).await {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                return Ok(());
            }
            return Err(e);
        }
        let len = u32::from_be_bytes(len_buf);
        if len > MAX_FRAME_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame too large: {}", len),
            ));
        }
        let mut buf = vec![0u8; len as usize];
        stream.read_exact(&mut buf).await?;
        let wire_id: BlakeId = blake3::hash(&buf).into();
        let now_ms = chrono_now_ms();
        let item = InboundBytes {
            wire_id,
            bytes: buf,
            // We don't yet know which endpoint sent this — that is
            // recovered by `connection.unwrap`. Leave None and let the
            // upper layer fill in observation rows.
            remote_endpoint_id: None,
            source_ip: Some(peer.ip().to_string()),
            source_port: Some(peer.port()),
            received_at_ms: now_ms,
        };
        if tx.send(InboundDelivery { work_item: item }).await.is_err() {
            // Receiver gone -> shut down loop.
            return Ok(());
        }
    }
}

fn chrono_now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip_frame() {
        let cache = SocketCache::new();
        let book = super::super::addrs::AddressBook::new();
        let (tx, mut rx) = mpsc::channel::<InboundDelivery>(8);

        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let local = accept_loop(bind, tx).await.unwrap();

        let local_endpoint: EndpointId = [1u8; 32];
        let remote_endpoint: EndpointId = [2u8; 32];
        book.insert(remote_endpoint, local);

        let frame = OutboundFrame::for_test_only(b"hello".to_vec());
        send(&cache, &book, local_endpoint, remote_endpoint, frame)
            .await
            .unwrap();

        let got = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.work_item.bytes, b"hello");
    }
}
