//! Bootstrap response network-send intent.
//!
//! `create_connection_response` commits responder material and the canonical
//! local response fact before queuing this local intent. This handler performs
//! only the socket attempt: it reloads the committed response and responder
//! ephemeral secret, seals the response bytes, and asks core networking to send
//! them to the requester's bootstrap return address.

use std::net::SocketAddr;

use crate::core::effects::PipelineEffects;
use crate::core::intents::{retry_intent, HandlerContext, HandlerFactId, HandlerResult};
use crate::core::intents::{Intent, IntentHandler, IntentKind};
use crate::core::network::{self, NetworkTarget, OutboundFrame};
use crate::protocol::connection::bootstrap_response;
use crate::protocol::connection::request::create as addr;
use crate::protocol::connection::response::layout as response_layout;

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

    fn handle(&self, intent: &Intent, context: &HandlerContext<'_>) -> HandlerResult {
        let input = decode_send_bootstrap_connection_response(intent)?;
        let response_fact = context.require_fact(&input.response_id)?;
        let response = response_layout::decode_fact(response_fact.body())?;
        if response.responder_ephemeral_secret_fact_id != input.responder_ephemeral_secret_id {
            return Err(
                "send_bootstrap_connection_response ephemeral id does not match response".into(),
            );
        }
        let ephemeral_fact = context.require_fact(&input.responder_ephemeral_secret_id)?;
        let ephemeral = crate::protocol::connection::ephemeral_secret::layout::decode_fact(
            ephemeral_fact.body(),
        )?;
        if ephemeral.owner_endpoint != response.from_endpoint {
            return Err(
                "send_bootstrap_connection_response ephemeral owner does not match response".into(),
            );
        }
        if ephemeral.ephemeral_public_key != response.responder_ephemeral_public_key {
            return Err(
                "send_bootstrap_connection_response ephemeral public key does not match response"
                    .into(),
            );
        }
        let sealed = bootstrap_response::seal_connection_response(
            &response_fact.bytes,
            &ephemeral.ephemeral_private_key,
        )?;
        network::send(
            context.store()?,
            NetworkTarget::new(input.addr),
            OutboundFrame { bytes: sealed },
        )
        .map_err(|err| {
            retry_intent(format!(
                "send_bootstrap_connection_response tcp send: {err}"
            ))
        })?;
        Ok(PipelineEffects::new())
    }
}

fn send_bootstrap_connection_response_key(input: &SendBootstrapConnectionResponse) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:send-bootstrap-connection-response:v1:");
    hash.update(&input.response_id);
    hash.update(&input.responder_ephemeral_secret_id);
    hash.update(input.addr.to_string().as_bytes());
    hash.finalize().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_roundtrips() {
        let input = SendBootstrapConnectionResponse {
            response_id: [1; 32],
            responder_ephemeral_secret_id: [2; 32],
            addr: "127.0.0.1:41001".parse().unwrap(),
        };
        let intent = send_bootstrap_connection_response_intent(input).expect("intent");
        assert_eq!(
            decode_send_bootstrap_connection_response(&intent).expect("decode"),
            input
        );
    }
}
