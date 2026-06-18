//! Established-connection outgoing-frame queue intent.
//!
//! This local intent is the route-resolving outgoing boundary for
//! already-packaged connection-frame bytes produced by projection. The handler
//! resolves the connection route from local connection rows and stages the
//! opaque frame in core networking. If route context is unavailable, the local
//! send attempt is stale and commits no effects. TCP reachability belongs to the
//! core outgoing pump, not to this protocol handler.
//!
//! The payload is only `(routing_key, frame bytes)`, and the intent key is a
//! deterministic checksum over both fields. Change this file for route lookup,
//! stale local-send behavior, or outgoing network queue interaction. Change the
//! concrete connection frame fact families for frame byte semantics.

use crate::core::effects::RuntimeEffects;
use crate::core::intents::{Intent, IntentKind};
use crate::core::wire::{
    Reader as PayloadReader, WireError as PayloadError, Writer as PayloadWriter,
};

/// Stable intent kind for outgoing network frame queueing.
pub const QUEUE_OUTGOING_FRAME: &str = "queue_outgoing_frame";

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

/// Maximum frame size accepted by the handler. Mirrors the largest connection-frame
/// frame size class with a small headroom; oversized frames are rejected
/// before any route lookup or socket work is attempted.
pub const MAX_FRAME_BYTES: usize = 1 << 21; // 2 MiB

/// 32-byte routing key. May be a connection id or any other handle the
/// connection-layer dispatcher uses to select a socket. The handler treats the
/// bits only as route input.
pub type RoutingKey = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueueOutgoingFrame {
    /// Routing key for the destination socket / connection.
    pub routing_key: RoutingKey,
    /// Opaque outgoing frame bytes. Already packaged by a concrete frame family.
    pub frame: Vec<u8>,
}

pub fn queue_outgoing_frame_intent(input: QueueOutgoingFrame) -> Intent {
    let mut payload = PayloadWriter::with_capacity(32 + 4 + input.frame.len());
    payload.fixed(&input.routing_key);
    payload
        .bytes_u32be(&input.frame)
        .expect("queue_outgoing_frame payload fits u32");
    Intent::new(
        IntentKind::new(QUEUE_OUTGOING_FRAME).expect("valid outgoing frame queue intent kind"),
        queue_outgoing_frame_key(&input),
        payload.finish(),
    )
}

pub fn decode_queue_outgoing_frame(intent: &Intent) -> Result<QueueOutgoingFrame, String> {
    if intent.kind.as_str() != QUEUE_OUTGOING_FRAME {
        return Err("expected queue_outgoing_frame intent".into());
    }

    let mut reader = PayloadReader::new(&intent.payload);
    let routing_key = reader.array::<32>().map_err(payload_error)?;
    let frame = reader.bytes_u32be().map_err(payload_error)?.to_vec();
    reader.finish().map_err(payload_error)?;

    let input = QueueOutgoingFrame { routing_key, frame };
    if intent.key != queue_outgoing_frame_key(&input) {
        return Err("queue_outgoing_frame intent key does not match payload".into());
    }
    Ok(input)
}

/// Per-(routing_key, frame) intent key used to detect payload tampering.
pub fn queue_outgoing_frame_key(input: &QueueOutgoingFrame) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:queue-outgoing-frame:v1:");
    hash.update(&input.routing_key);
    hash.update(&(input.frame.len() as u32).to_be_bytes());
    hash.update(&input.frame);
    hash.finalize().as_bytes().to_vec()
}

fn payload_error(err: PayloadError) -> String {
    format!("invalid queue_outgoing_frame payload: {err}")
}

use crate::core::intents::{
    HandlerContext, HandlerError, HandlerFactId, HandlerResult, IntentHandler,
};
use crate::core::network::{self, NetworkTarget, OutgoingFrame};
use crate::protocol::{auth::endpoint, connection};

#[derive(Debug, Clone, Default)]
pub struct QueueOutgoingFrameHandler;

impl QueueOutgoingFrameHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for QueueOutgoingFrameHandler {
    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        decode_queue_outgoing_frame(intent)?;
        Ok(Vec::new())
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_queue_outgoing_frame(intent)?;
        validate_frame(&input)?;
        if context.is_replay() {
            return Ok(RuntimeEffects::new());
        }
        if let Some(target) = resolve_target(&input.routing_key, context)? {
            network::queue_outgoing_in_tx(
                context.db()?,
                target,
                OutgoingFrame { bytes: input.frame },
            )
            .map_err(|err| HandlerError::fatal(format!("queue_outgoing_frame enqueue: {err}")))?;
        }
        Ok(RuntimeEffects::new())
    }
}

fn validate_frame(input: &QueueOutgoingFrame) -> Result<(), String> {
    if input.frame.is_empty() {
        return Err("queue_outgoing_frame: frame bytes are empty".into());
    }
    if input.frame.len() > MAX_FRAME_BYTES {
        return Err(format!(
            "queue_outgoing_frame: frame size {} exceeds max {MAX_FRAME_BYTES}",
            input.frame.len()
        ));
    }
    Ok(())
}

fn resolve_target(
    connection_id: &RoutingKey,
    context: &HandlerContext,
) -> Result<Option<NetworkTarget>, HandlerError> {
    resolve_connection_row_target(connection_id, context)
}

fn resolve_connection_row_target(
    connection_id: &RoutingKey,
    context: &HandlerContext,
) -> Result<Option<NetworkTarget>, HandlerError> {
    let Some(connection) =
        connection::connection::queries::connection_by_id(context.db()?, connection_id).map_err(
            |err| HandlerError::fatal(format!("queue_outgoing_frame route row read: {err}")),
        )?
    else {
        return Ok(None);
    };
    let local_endpoint = endpoint::author::local_endpoint(context.db()?)?
        .ok_or_else(|| HandlerError::fatal("queue_outgoing_frame requires local endpoint state"))?;
    let addr = if local_endpoint.endpoint == connection.from_endpoint {
        connection.initiator_addr
    } else if local_endpoint.endpoint == connection.to_endpoint {
        connection.responder_addr
    } else {
        return Err("queue_outgoing_frame local endpoint is not part of connection".into());
    };
    let Some(addr) = addr else {
        return Ok(None);
    };
    Ok(Some(NetworkTarget::new(addr)))
}
