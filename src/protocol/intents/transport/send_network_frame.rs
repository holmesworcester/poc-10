//! Outbound network-send handler.
//!
//! Owns the ephemeral intent that asks the runtime to push an already-packaged
//! transport::transit frame onto a connection's TCP socket. The handler resolves the
//! connection route from the fact context, stages the frame through core's
//! outbound queue boundary, and attempts one bounded TCP write. If route
//! context or the socket is unavailable, the handler asks the wake loop to keep
//! the intent visible in the current process so the next sync/daemon pass can
//! try again without making network delivery durable protocol state.

//! Send-network-frame intent layout.
//!
//! The intent carries a routing key (connection id) and the opaque transport::transit
//! frame bytes that the runtime should push onto that connection's socket.
//! Codec uses a hand-rolled length-prefix format — `core/wire` is intentionally
//! not imported here so the handler stays decoupled from on-the-wire layouts.

use crate::core::intents::{Intent, IntentExecution, IntentKind};

/// Stable intent kind for outbound network frame sends.
pub const SEND_NETWORK_FRAME: &str = "send_network_frame";

/// Maximum frame size accepted by the handler. Mirrors the largest transport::transit
/// frame size class with a small headroom; oversized frames are rejected
/// before any cursor work is attempted.
pub const MAX_FRAME_BYTES: usize = 1 << 21; // 2 MiB

/// 32-byte routing key. May be a connection id or any other handle the
/// connection-layer dispatcher uses to select a socket. The handler does not
/// interpret the bits — they are only an idempotence dimension.
pub type RoutingKey = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendNetworkFrame {
    /// Routing key for the destination socket / connection.
    pub routing_key: RoutingKey,
    /// Opaque outbound frame bytes. Already packaged by the transport::transit layer.
    pub frame: Vec<u8>,
}

pub fn send_network_frame_intent(input: SendNetworkFrame) -> Intent {
    let mut payload = Vec::with_capacity(32 + 4 + input.frame.len());
    payload.extend_from_slice(&input.routing_key);
    push_bytes(&mut payload, &input.frame);
    Intent::new(
        IntentKind::new(SEND_NETWORK_FRAME).expect("valid send network frame intent kind"),
        IntentExecution::Ephemeral,
        send_network_frame_key(&input),
        payload,
    )
}

pub fn decode_send_network_frame(intent: &Intent) -> Result<SendNetworkFrame, String> {
    if intent.kind.as_str() != SEND_NETWORK_FRAME {
        return Err("expected send_network_frame intent".to_string());
    }
    if intent.execution != IntentExecution::Ephemeral {
        return Err("send_network_frame intent must be ephemeral".to_string());
    }

    let mut reader = Reader::new(&intent.payload);
    let routing_bytes = reader.take(32)?;
    let mut routing_key = [0u8; 32];
    routing_key.copy_from_slice(routing_bytes);
    let frame = reader.bytes()?.to_vec();
    reader.finish()?;

    let input = SendNetworkFrame { routing_key, frame };
    if intent.key != send_network_frame_key(&input) {
        return Err("send_network_frame idempotence key does not match payload".to_string());
    }
    Ok(input)
}

/// Per-(routing_key, frame) idempotence key. Two intents for the same routing
/// key carrying the same frame bytes produce the same intent key, which lets
/// the deferred-intent layer collapse duplicates before the handler runs.
pub fn send_network_frame_key(input: &SendNetworkFrame) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:send-network-frame:v1:");
    hash.update(&input.routing_key);
    hash.update(&(input.frame.len() as u32).to_be_bytes());
    hash.update(&input.frame);
    hash.finalize().as_bytes().to_vec()
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
            .ok_or_else(|| "send_network_frame payload length overflow".to_string())?;
        if end > self.bytes.len() {
            return Err("truncated send_network_frame payload".to_string());
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn finish(self) -> Result<(), String> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err("send_network_frame payload has trailing bytes".to_string())
        }
    }
}

use crate::core::handler_dispatch::{
    retry_intent, HandlerContext, HandlerFactId, HandlerOutput, IntentHandler,
};
use crate::core::network_queues::{NetworkTarget, OutboundNetworkRow};
use crate::core::tcp;
use crate::protocol::facts::{connection, identity::endpoint};

pub const SEND_NETWORK_FRAME_MISSING_ROUTE: &str = "send_network_frame_missing_route";

#[derive(Debug, Clone, Default)]
pub struct SendNetworkFrameHandler;

impl SendNetworkFrameHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for SendNetworkFrameHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == SEND_NETWORK_FRAME
    }

    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_send_network_frame(intent)?;
        Ok(vec![input.routing_key])
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = decode_send_network_frame(intent)?;
        validate_frame(&input)?;
        let target = match resolve_target(&input.routing_key, context) {
            Ok(target) => target,
            Err(err)
                if err == SEND_NETWORK_FRAME_MISSING_ROUTE
                    || err == "send_network_frame missing connection request fact" =>
            {
                return Err(retry_intent(format!(
                    "send_network_frame route unavailable: {err}"
                )));
            }
            Err(err) => return Err(err),
        };
        let row = OutboundNetworkRow::new(target, input.frame);
        tcp::send_once(context.store()?, target, vec![row], (), |_, _| Ok(()))
            .map_err(|err| retry_intent(format!("send_network_frame tcp send: {err}")))?;
        Ok(HandlerOutput::new())
    }
}

fn validate_frame(input: &SendNetworkFrame) -> Result<(), String> {
    if input.frame.is_empty() {
        return Err("send_network_frame: frame bytes are empty".to_string());
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
) -> Result<NetworkTarget, String> {
    let connection_fact = context.require_fact(connection_id)?;
    let connection = connection::response::layout::decode_fact(connection_fact.body())?;
    let request_fact = match context.fact(&connection.request_id).cloned() {
        Some(fact) => fact,
        None => crate::core::wake_loop::persisted_fact(context.store()?, &connection.request_id)?
            .ok_or_else(|| "send_network_frame missing connection request fact".to_string())?,
    };
    let request = connection::request::layout::decode_fact(request_fact.body())?;
    let local_endpoint = endpoint::local_endpoint::local_endpoint(context.store()?)?
        .ok_or_else(|| "send_network_frame requires local endpoint state".to_string())?;
    let addr = if local_endpoint.endpoint == connection.from_endpoint {
        request.from_listen_addr
    } else if local_endpoint.endpoint == connection.to_endpoint {
        request.to_listen_addr
    } else {
        return Err("send_network_frame local endpoint is not part of connection".to_string());
    };
    let Some(addr) = addr else {
        return Err(SEND_NETWORK_FRAME_MISSING_ROUTE.to_string());
    };
    Ok(NetworkTarget::new(addr))
}
