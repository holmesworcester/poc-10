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
//! behavior, or outbound network queue interaction. Change connection-frame
//! protocol helpers for frame byte semantics.

use crate::core::effects::PipelineEffects;
use crate::core::intents::{Intent, IntentKind};
use crate::protocol::payload::{PayloadError, PayloadReader, PayloadWriter};

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
    /// Opaque outbound frame bytes. Already packaged by connection-frame helpers.
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
use crate::protocol::connection::bootstrap_response::fact::BootstrapResponseFact;
use crate::protocol::connection::observed_endpoint_address::queries::observed_endpoint_address;
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
        let input = decode_send_network_frame(intent)?;
        Ok(vec![input.routing_key])
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_send_network_frame(intent)?;
        validate_frame(&input)?;
        // The routing key is either an established/handshake connection fact id or,
        // before any connection exists, the peer endpoint id. If it resolves to
        // neither a live connection nor a learned peer address, the route is gone
        // (e.g. a closed connection): drop the send silently rather than retry.
        let Some(target) = resolve_target(&input.routing_key, context)? else {
            return Ok(PipelineEffects::new());
        };
        network::send(
            context.store()?,
            target,
            OutboundFrame { bytes: input.frame },
        )
        .map_err(|err| retry_intent(format!("send_network_frame tcp send: {err}")))?;
        Ok(PipelineEffects::new())
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
    routing_key: &RoutingKey,
    context: &HandlerContext,
) -> Result<Option<NetworkTarget>, HandlerError> {
    // Established (and self-authored bootstrap response) frames route by a
    // connection fact id: derive the return route from the answered request fact.
    if let Some(connection) = load_connection(routing_key, context)? {
        return resolve_established_target(&connection, context).map(Some);
    }
    // Before a connection exists, the routing key is the peer endpoint id itself:
    // resolve its learned listen address directly.
    if let Some(addr) = observed_endpoint_address(context.store()?, routing_key)? {
        return Ok(Some(NetworkTarget::new(addr)));
    }
    // Neither a live connection nor a learned peer address: no route.
    Ok(None)
}

/// Decode the connection named by `routing_key`, if the key is a connection id at
/// all. A peer endpoint id (the pre-connection request route) is not a connection
/// fact, so this returns `None` for it.
fn load_connection(
    routing_key: &RoutingKey,
    context: &HandlerContext,
) -> Result<Option<BootstrapResponseFact>, HandlerError> {
    let decoded = match context.fact(routing_key) {
        Some(fact) => connection::bootstrap_response::layout::decode_fact(fact.body()).ok(),
        None => crate::core::fact_store::persisted_fact(context.store()?, routing_key)?
            .and_then(|fact| connection::bootstrap_response::layout::decode_fact(fact.body()).ok()),
    };
    Ok(decoded)
}

fn resolve_established_target(
    connection: &BootstrapResponseFact,
    context: &HandlerContext,
) -> Result<NetworkTarget, HandlerError> {
    let request_bytes = match context.fact(&connection.request_id) {
        Some(fact) => fact.body().to_vec(),
        None => crate::core::fact_store::persisted_fact(context.store()?, &connection.request_id)?
            .ok_or_else(|| {
                retry_intent(
                    "send_network_frame route: send_network_frame missing connection request fact",
                )
            })?
            .body()
            .to_vec(),
    };
    let request = connection::bootstrap_request::layout::decode_fact(&request_bytes)?;
    let local_endpoint = endpoint::create::local_endpoint(context.store()?)?
        .ok_or_else(|| HandlerError::fatal("send_network_frame requires local endpoint state"))?;
    let addr = if local_endpoint.endpoint == connection.from_endpoint {
        request.from_listen_addr
    } else if local_endpoint.endpoint == connection.to_endpoint {
        request.to_listen_addr
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
