//! Network-send intent layout.
//!
//! The intent carries a routing key (connection id) and the opaque transit
//! frame bytes that the runtime should push onto that connection's socket.
//! Codec uses a hand-rolled length-prefix format — `core/wire` is intentionally
//! not imported here so the handler stays decoupled from on-the-wire layouts.

use crate::core::intents::{Intent, IntentExecution, IntentKind};

/// Stable intent kind for outbound network frame sends.
pub const NETWORK_SEND_FRAME: &str = "network_send";

/// Maximum frame size accepted by the handler. Mirrors the largest transit
/// frame size class with a small headroom; oversized frames are rejected
/// before any cursor work is attempted.
pub const MAX_FRAME_BYTES: usize = 1 << 21; // 2 MiB

/// 32-byte routing key. May be a connection id or any other handle the
/// connection-layer dispatcher uses to select a socket. The handler does not
/// interpret the bits — they are only an idempotence dimension.
pub type RoutingKey = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkSendFrame {
    /// Routing key for the destination socket / connection.
    pub routing_key: RoutingKey,
    /// Opaque outbound frame bytes. Already packaged by the transit layer.
    pub frame: Vec<u8>,
}

pub fn network_send_frame_intent(input: NetworkSendFrame) -> Intent {
    let mut payload = Vec::with_capacity(32 + 4 + input.frame.len());
    payload.extend_from_slice(&input.routing_key);
    push_bytes(&mut payload, &input.frame);
    Intent::new(
        IntentKind::new(NETWORK_SEND_FRAME).expect("valid network send intent kind"),
        IntentExecution::Deferred,
        network_send_key(&input),
        payload,
    )
}

pub fn decode_network_send_frame(intent: &Intent) -> Result<NetworkSendFrame, String> {
    if intent.kind.as_str() != NETWORK_SEND_FRAME {
        return Err("expected network_send intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("network_send intent must be deferred".to_string());
    }

    let mut reader = Reader::new(&intent.payload);
    let routing_bytes = reader.take(32)?;
    let mut routing_key = [0u8; 32];
    routing_key.copy_from_slice(routing_bytes);
    let frame = reader.bytes()?.to_vec();
    reader.finish()?;

    let input = NetworkSendFrame { routing_key, frame };
    if intent.key != network_send_key(&input) {
        return Err("network_send idempotence key does not match payload".to_string());
    }
    Ok(input)
}

/// Per-(routing_key, frame) idempotence key. Two intents for the same routing
/// key carrying the same frame bytes produce the same intent key, which lets
/// the deferred-intent layer collapse duplicates before the handler runs.
pub fn network_send_key(input: &NetworkSendFrame) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:network-send-frame:v1:");
    hash.update(&input.routing_key);
    hash.update(&(input.frame.len() as u32).to_be_bytes());
    hash.update(&input.frame);
    hash.finalize().as_bytes().to_vec()
}

/// Deterministic digest of the frame bytes used by the cursor fact value.
pub fn frame_digest(frame: &[u8]) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:network-send-frame-digest:v1:");
    hash.update(&(frame.len() as u32).to_be_bytes());
    hash.update(frame);
    *hash.finalize().as_bytes()
}

fn push_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn u32(&mut self) -> Result<u32, String> {
        let bytes = self.take(4)?;
        Ok(u32::from_be_bytes(bytes.try_into().unwrap()))
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| "network_send payload length overflow".to_string())?;
        if end > self.bytes.len() {
            return Err("truncated network_send payload".to_string());
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn finish(self) -> Result<(), String> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err("network_send payload has trailing bytes".to_string())
        }
    }
}
