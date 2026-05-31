//! Bootstrap response network-send intent.
//!
//! The responder creates its ephemeral and `bootstrap_response` facts and the
//! local response projector emits this send intent once that response fact is
//! admitted — flat, with no handler-to-handler chain. The handler loads the
//! committed response fact and its responder ephemeral secret, seals the
//! response bytes responder-ephemeral → initiator-endpoint, and attempts one
//! bounded write to the initiator's bootstrap return address.
//!
//! The intent key is the response id, so duplicate sends of one response
//! collapse. This is operational network IO: it never runs during replay, and a
//! lost send is recovered by a later live retry from the committed response.

use std::net::SocketAddr;

use crate::core::effects::PipelineEffects;
use crate::core::intents::{HandlerContext, HandlerFactId, HandlerResult, IntentHandler};
use crate::core::intents::{Intent, IntentKind};
use crate::core::network::{self, NetworkTarget, OutboundFrame};
use crate::protocol::connection::bootstrap_request::create as addr;
use crate::protocol::connection::bootstrap_response::layout as response_layout;
use crate::protocol::connection::bootstrap_response::transit as response_transit;
use crate::protocol::connection::ephemeral_secret::layout as ephemeral_layout;

pub const SEND_BOOTSTRAP_CONNECTION_RESPONSE: &str = "send_bootstrap_connection_response";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendBootstrapConnectionResponse {
    pub response_id: [u8; 32],
    pub responder_ephemeral_secret_id: [u8; 32],
    pub addr: SocketAddr,
}

pub fn send_bootstrap_connection_response_intent(
    input: SendBootstrapConnectionResponse,
) -> Result<Intent, String> {
    let mut payload = Vec::with_capacity(1 + 32 + 32 + addr::ADDR_BLOCK_BYTES);
    payload.push(1);
    payload.extend_from_slice(&input.response_id);
    payload.extend_from_slice(&input.responder_ephemeral_secret_id);
    payload.extend_from_slice(&addr::encode_optional_addr(Some(input.addr))?);
    Ok(Intent::new(
        IntentKind::new(SEND_BOOTSTRAP_CONNECTION_RESPONSE)
            .expect("valid send bootstrap connection response intent kind"),
        send_bootstrap_connection_response_key(&input),
        payload,
    ))
}

pub fn decode_send_bootstrap_connection_response(
    intent: &Intent,
) -> Result<SendBootstrapConnectionResponse, String> {
    if intent.kind.as_str() != SEND_BOOTSTRAP_CONNECTION_RESPONSE {
        return Err("expected send_bootstrap_connection_response intent".into());
    }
    if intent.payload.len() != 1 + 32 + 32 + addr::ADDR_BLOCK_BYTES {
        return Err("send_bootstrap_connection_response payload has wrong length".into());
    }
    if intent.payload[0] != 1 {
        return Err("send_bootstrap_connection_response payload version unsupported".into());
    }
    let response_id = intent.payload[1..33].try_into().unwrap();
    let responder_ephemeral_secret_id = intent.payload[33..65].try_into().unwrap();
    let mut addr_bytes = [0; addr::ADDR_BLOCK_BYTES];
    addr_bytes.copy_from_slice(&intent.payload[65..]);
    let addr = addr::decode_optional_addr(&addr_bytes)?
        .ok_or_else(|| "send_bootstrap_connection_response addr is missing".to_string())?;
    let input = SendBootstrapConnectionResponse {
        response_id,
        responder_ephemeral_secret_id,
        addr,
    };
    if intent.key != send_bootstrap_connection_response_key(&input) {
        return Err("send_bootstrap_connection_response key does not match payload".into());
    }
    Ok(input)
}

#[derive(Debug, Clone, Default)]
pub struct SendBootstrapConnectionResponseHandler;

impl SendBootstrapConnectionResponseHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for SendBootstrapConnectionResponseHandler {
    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_send_bootstrap_connection_response(intent)?;
        Ok(vec![input.response_id, input.responder_ephemeral_secret_id])
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_send_bootstrap_connection_response(intent)?;
        let response_fact = context.require_fact(&input.response_id)?;
        let response = response_layout::decode_fact(response_fact.body())?;
        if response.responder_ephemeral_secret_fact_id != input.responder_ephemeral_secret_id {
            return Err(
                "send_bootstrap_connection_response ephemeral id does not match response".into(),
            );
        }
        let ephemeral_fact = context.require_fact(&input.responder_ephemeral_secret_id)?;
        let ephemeral = ephemeral_layout::decode_fact(ephemeral_fact.body())?;
        if ephemeral.ephemeral_public_key != response.responder_ephemeral_public_key {
            return Err(
                "send_bootstrap_connection_response ephemeral public key does not match response"
                    .into(),
            );
        }
        let sealed = response_transit::seal_connection_response(
            response_fact.body(),
            &ephemeral.ephemeral_private_key,
        )?;
        let target = NetworkTarget::new(input.addr);
        // A lost send is recovered by a later live retry from the committed
        // response fact, so a transport failure consumes the attempt.
        if network::send(context.store()?, target, OutboundFrame { bytes: sealed }).is_err() {
            return Ok(PipelineEffects::new());
        }
        Ok(PipelineEffects::new())
    }
}

fn send_bootstrap_connection_response_key(input: &SendBootstrapConnectionResponse) -> Vec<u8> {
    // The response id is the unit of work: only one sealed send per response.
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:send-bootstrap-connection-response:v1:");
    hash.update(&input.response_id);
    hash.finalize().as_bytes().to_vec()
}
