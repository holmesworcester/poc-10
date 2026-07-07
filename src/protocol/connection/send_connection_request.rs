//! Membership connection-request network-send intent.
//!
//! Before a membership connection exists, the only outbound network operation is
//! sending a `connection_request` fact to the endpoint's learned listen address.
//! The live `maintain_connections` recurring loop emits this local intent for
//! each unanswered local outbound membership request; the handler loads exactly
//! that request fact plus its initiator ephemeral secret, seals the canonical
//! bytes through the connection transport, and emits a `send_network_frame`
//! intent keyed by the peer endpoint — the single outgoing socket boundary,
//! identical to established-frame egress. Retry timing is the maintenance
//! cadence: a dropped send is re-queued on the next tick.

use std::net::SocketAddr;

use crate::core::effects::PipelineEffects;
use crate::core::intents::{HandlerContext, HandlerFactId, HandlerResult, IntentHandler};
use crate::core::intents::{Intent, IntentKind};
use crate::protocol::connection::bootstrap_request::create as addr;
use crate::protocol::connection::connection_request::decode as layout;
use crate::protocol::connection::send_network_frame::{
    send_network_frame_intent, SendNetworkFrame,
};
use crate::protocol::connection_frame::seal_handshake_request;

pub const SEND_CONNECTION_REQUEST: &str = "send_connection_request";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendConnectionRequest {
    pub request_id: [u8; 32],
    pub initiator_ephemeral_secret_id: [u8; 32],
    pub addr: SocketAddr,
}

pub fn send_connection_request_intent(input: SendConnectionRequest) -> Result<Intent, String> {
    let mut payload = Vec::with_capacity(1 + 32 + 32 + addr::ADDR_BLOCK_BYTES);
    payload.push(1);
    payload.extend_from_slice(&input.request_id);
    payload.extend_from_slice(&input.initiator_ephemeral_secret_id);
    payload.extend_from_slice(&addr::encode_optional_addr(Some(input.addr))?);
    Ok(Intent::new(
        IntentKind::new(SEND_CONNECTION_REQUEST)
            .expect("valid send connection request intent kind"),
        send_connection_request_key(&input),
        payload,
    ))
}

pub fn decode_send_connection_request(intent: &Intent) -> Result<SendConnectionRequest, String> {
    if intent.kind.as_str() != SEND_CONNECTION_REQUEST {
        return Err("expected send_connection_request intent".into());
    }
    if intent.payload.len() != 1 + 32 + 32 + addr::ADDR_BLOCK_BYTES {
        return Err("send_connection_request payload has wrong length".into());
    }
    if intent.payload[0] != 1 {
        return Err("send_connection_request payload version unsupported".into());
    }
    let request_id = intent.payload[1..33].try_into().unwrap();
    let initiator_ephemeral_secret_id = intent.payload[33..65].try_into().unwrap();
    let mut addr_bytes = [0; addr::ADDR_BLOCK_BYTES];
    addr_bytes.copy_from_slice(&intent.payload[65..]);
    let addr = addr::decode_optional_addr(&addr_bytes)?
        .ok_or_else(|| "send_connection_request addr is missing".to_string())?;
    let input = SendConnectionRequest {
        request_id,
        initiator_ephemeral_secret_id,
        addr,
    };
    if intent.key != send_connection_request_key(&input) {
        return Err("send_connection_request key does not match payload".into());
    }
    Ok(input)
}

#[derive(Debug, Clone, Default)]
pub struct SendConnectionRequestHandler;

impl SendConnectionRequestHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for SendConnectionRequestHandler {
    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_send_connection_request(intent)?;
        Ok(vec![input.request_id, input.initiator_ephemeral_secret_id])
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_send_connection_request(intent)?;
        let request_fact = context.require_fact(&input.request_id)?;
        let request = layout::decode_fact(request_fact.body())?;
        if request.initiator_ephemeral_secret_fact_id != input.initiator_ephemeral_secret_id {
            return Err("send_connection_request ephemeral id does not match request".into());
        }
        let ephemeral_fact = context.require_fact(&input.initiator_ephemeral_secret_id)?;
        let ephemeral = crate::protocol::connection::ephemeral_secret::layout::decode_fact(
            ephemeral_fact.body(),
        )?;
        if ephemeral.owner_endpoint != request.from_endpoint {
            return Err("send_connection_request ephemeral owner does not match request".into());
        }
        if ephemeral.ephemeral_public_key != request.initiator_ephemeral_public_key {
            return Err(
                "send_connection_request ephemeral public key does not match request".into(),
            );
        }
        let sealed = seal_handshake_request(request_fact.body(), &ephemeral.ephemeral_private_key)?;
        // Egress is the connection frame boundary: seal here, then hand the bytes
        // to `send_network_frame` keyed by the peer endpoint so the socket write
        // happens in exactly one place. The peer's reachable address is resolved
        // from its learned `observed_endpoint_address` row there.
        Ok(
            PipelineEffects::new().local_intent(send_network_frame_intent(SendNetworkFrame {
                routing_key: request.to_endpoint,
                frame: sealed,
            })),
        )
    }
}

fn send_connection_request_key(input: &SendConnectionRequest) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:send-membership-connection-request:v1:");
    hash.update(&input.request_id);
    hash.update(&input.initiator_ephemeral_secret_id);
    hash.update(input.addr.to_string().as_bytes());
    hash.finalize().as_bytes().to_vec()
}
