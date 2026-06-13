//! Established-connection network-send intent.
//!
//! This local intent is the final outgoing boundary for already-packaged
//! connection-frame bytes. The handler resolves the connection route from local
//! context, stages the opaque frame in core networking, and attempts one bounded
//! TCP write. If route context or the socket is unavailable, it asks the intent
//! runtime to retry instead of making network delivery durable protocol truth.
//!
//! The payload is only `(routing_key, frame bytes)`, and the idempotence key is
//! deterministic over both fields. Change this file for route lookup, retry
//! behavior, or outbound network queue interaction. Change the concrete
//! connection frame fact families for frame byte semantics.

use crate::core::effects::RuntimeEffects;
use crate::core::intents::{Intent, IntentKind};
use crate::core::wire::{
    Reader as PayloadReader, WireError as PayloadError, Writer as PayloadWriter,
};

/// Stable intent kind for outbound network frame sends.
pub const SEND_NETWORK_FRAME: &str = "send_network_frame";

/// Maximum frame size accepted by the handler. Mirrors the largest connection-frame
/// frame size class with a small headroom; oversized frames are rejected
/// before any route lookup or socket work is attempted.
pub const MAX_FRAME_BYTES: usize = 1 << 21; // 2 MiB

/// 32-byte routing key. May be a connection id or any other handle the
/// connection-layer dispatcher uses to select a socket. The handler treats the
/// bits only as an idempotence dimension.
pub type RoutingKey = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendNetworkFrame {
    /// Routing key for the destination socket / connection.
    pub routing_key: RoutingKey,
    /// Opaque outbound frame bytes. Already packaged by a concrete frame family.
    pub frame: Vec<u8>,
}

pub fn send_network_frame_intent(input: SendNetworkFrame) -> Intent {
    let mut payload = PayloadWriter::with_capacity(32 + 4 + input.frame.len());
    payload.fixed(&input.routing_key);
    payload
        .bytes_u32be(&input.frame)
        .expect("send_network_frame payload fits u32");
    Intent::new(
        IntentKind::new(SEND_NETWORK_FRAME).expect("valid send network frame intent kind"),
        send_network_frame_key(&input),
        payload.finish(),
    )
}

pub fn decode_send_network_frame(intent: &Intent) -> Result<SendNetworkFrame, String> {
    if intent.kind.as_str() != SEND_NETWORK_FRAME {
        return Err("expected send_network_frame intent".into());
    }

    let mut reader = PayloadReader::new(&intent.payload);
    let routing_key = reader.array::<32>().map_err(payload_error)?;
    let frame = reader.bytes_u32be().map_err(payload_error)?.to_vec();
    reader.finish().map_err(payload_error)?;

    let input = SendNetworkFrame { routing_key, frame };
    if intent.key != send_network_frame_key(&input) {
        return Err("send_network_frame idempotence key does not match payload".into());
    }
    Ok(input)
}

/// Per-(routing_key, frame) idempotence key. Two intents for the same routing
/// key carrying the same frame bytes produce the same intent key, which lets
/// the intent queue collapse duplicates before the handler runs.
pub fn send_network_frame_key(input: &SendNetworkFrame) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:send-network-frame:v1:");
    hash.update(&input.routing_key);
    hash.update(&(input.frame.len() as u32).to_be_bytes());
    hash.update(&input.frame);
    hash.finalize().as_bytes().to_vec()
}

fn payload_error(err: PayloadError) -> String {
    format!("invalid send_network_frame payload: {err}")
}

use crate::core::intents::{
    retry_intent, HandlerContext, HandlerError, HandlerFactId, HandlerResult, IntentHandler,
};
use crate::core::network::{self, NetworkTarget, OutboundFrame};
use crate::protocol::{auth::endpoint, connection};

pub const SEND_NETWORK_FRAME_MISSING_ROUTE: &str = "send_network_frame_missing_route";

#[derive(Debug, Clone, Default)]
pub struct SendNetworkFrameHandler;

impl SendNetworkFrameHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for SendNetworkFrameHandler {
    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        decode_send_network_frame(intent)?;
        Ok(Vec::new())
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_send_network_frame(intent)?;
        validate_frame(&input)?;
        let target = resolve_target(&input.routing_key, context)?;
        network::send(
            context.store()?,
            target,
            OutboundFrame { bytes: input.frame },
        )
        .map_err(|err| retry_intent(format!("send_network_frame tcp send: {err}")))?;
        Ok(RuntimeEffects::new())
    }
}

fn validate_frame(input: &SendNetworkFrame) -> Result<(), String> {
    if input.frame.is_empty() {
        return Err("send_network_frame: frame bytes are empty".into());
    }
    if input.frame.len() > MAX_FRAME_BYTES {
        return Err(format!(
            "send_network_frame: frame size {} exceeds max {MAX_FRAME_BYTES}",
            input.frame.len()
        ));
    }
    Ok(())
}

fn resolve_target(
    connection_id: &RoutingKey,
    context: &HandlerContext,
) -> Result<NetworkTarget, HandlerError> {
    if let Some(target) = resolve_connection_request_row_target(connection_id, context)? {
        return Ok(target);
    }
    resolve_connection_row_target(connection_id, context)
}

fn resolve_connection_request_row_target(
    request_id: &RoutingKey,
    context: &HandlerContext,
) -> Result<Option<NetworkTarget>, HandlerError> {
    let Some(row) = connection::request::queries::request_by_id(context.store()?, request_id)
        .map_err(|err| {
            HandlerError::fatal(format!("send_network_frame request row read: {err}"))
        })?
    else {
        return Ok(None);
    };
    let Some(addr) = row.peer_addr else {
        return Err(retry_intent(format!(
            "send_network_frame route: {SEND_NETWORK_FRAME_MISSING_ROUTE}"
        )));
    };
    Ok(Some(NetworkTarget::new(addr)))
}

fn resolve_connection_row_target(
    connection_id: &RoutingKey,
    context: &HandlerContext,
) -> Result<NetworkTarget, HandlerError> {
    let Some(connection) =
        connection::connection::queries::connection_by_id(context.store()?, connection_id)
            .map_err(|err| {
                HandlerError::fatal(format!("send_network_frame route row read: {err}"))
            })?
    else {
        return Err(retry_intent(
            "send_network_frame route: send_network_frame missing connection row",
        ));
    };
    let local_endpoint = endpoint::author::local_endpoint(context.store()?)?
        .ok_or_else(|| HandlerError::fatal("send_network_frame requires local endpoint state"))?;
    let addr = if local_endpoint.endpoint == connection.from_endpoint {
        connection.initiator_addr
    } else if local_endpoint.endpoint == connection.to_endpoint {
        connection.responder_addr
    } else {
        return Err("send_network_frame local endpoint is not part of connection".into());
    };
    let Some(addr) = addr else {
        return Err(retry_intent(format!(
            "send_network_frame route: {SEND_NETWORK_FRAME_MISSING_ROUTE}"
        )));
    };
    Ok(NetworkTarget::new(addr))
}
