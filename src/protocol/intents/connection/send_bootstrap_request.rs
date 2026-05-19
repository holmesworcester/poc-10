//! Send bootstrap connection request handler.
//!
//! This handler owns the one pre-connection network effect: sending a validated
//! `connection::request` fact to the address carried by an invite link. Once the
//! request/response handshake establishes a connection, ordinary transit frames
//! and `send_network_frame` take over.

use std::net::SocketAddr;

use crate::core::handler_dispatch::{
    retry_intent, HandlerContext, HandlerFactId, HandlerOutput, IntentHandler,
};
use crate::core::intents::{Intent, IntentExecution, IntentKind};
use crate::core::network_queues::{NetworkTarget, OutboundNetworkRow};
use crate::core::tcp;
use crate::protocol::facts::connection::request::{addr, layout};

pub const SEND_BOOTSTRAP_CONNECTION_REQUEST: &str = "send_bootstrap_connection_request";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendBootstrapConnectionRequest {
    pub request_id: [u8; 32],
    pub addr: SocketAddr,
}

pub fn send_bootstrap_connection_request_intent(
    input: SendBootstrapConnectionRequest,
) -> Result<Intent, String> {
    let mut payload = Vec::with_capacity(1 + 32 + addr::ADDR_BLOCK_BYTES);
    payload.push(1);
    payload.extend_from_slice(&input.request_id);
    payload.extend_from_slice(&addr::encode_optional_addr(Some(input.addr))?);
    Ok(Intent::new(
        IntentKind::new(SEND_BOOTSTRAP_CONNECTION_REQUEST)
            .expect("valid send bootstrap connection request intent kind"),
        IntentExecution::Ephemeral,
        send_bootstrap_connection_request_key(&input),
        payload,
    ))
}

pub fn decode_send_bootstrap_connection_request(
    intent: &Intent,
) -> Result<SendBootstrapConnectionRequest, String> {
    if intent.kind.as_str() != SEND_BOOTSTRAP_CONNECTION_REQUEST {
        return Err("expected send_bootstrap_connection_request intent".to_string());
    }
    if intent.execution != IntentExecution::Ephemeral {
        return Err("send_bootstrap_connection_request intent must be ephemeral".to_string());
    }
    if intent.payload.len() != 1 + 32 + addr::ADDR_BLOCK_BYTES {
        return Err("send_bootstrap_connection_request payload has wrong length".to_string());
    }
    if intent.payload[0] != 1 {
        return Err("send_bootstrap_connection_request payload version unsupported".to_string());
    }
    let request_id = intent.payload[1..33].try_into().unwrap();
    let mut addr_bytes = [0; addr::ADDR_BLOCK_BYTES];
    addr_bytes.copy_from_slice(&intent.payload[33..]);
    let addr = addr::decode_optional_addr(&addr_bytes)?
        .ok_or_else(|| "send_bootstrap_connection_request addr is missing".to_string())?;
    let input = SendBootstrapConnectionRequest { request_id, addr };
    if intent.key != send_bootstrap_connection_request_key(&input) {
        return Err("send_bootstrap_connection_request key does not match payload".to_string());
    }
    Ok(input)
}

#[derive(Debug, Clone, Default)]
pub struct SendBootstrapConnectionRequestHandler;

impl SendBootstrapConnectionRequestHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for SendBootstrapConnectionRequestHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == SEND_BOOTSTRAP_CONNECTION_REQUEST
    }

    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        Ok(vec![
            decode_send_bootstrap_connection_request(intent)?.request_id,
        ])
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = decode_send_bootstrap_connection_request(intent)?;
        let request_fact = context.require_fact(&input.request_id)?;
        layout::decode_fact(request_fact.body())?;
        let target = NetworkTarget::new(input.addr);
        let row = OutboundNetworkRow::new(target, request_fact.bytes.clone());
        tcp::send_once(context.store()?, target, vec![row], (), |_, _| Ok(())).map_err(|err| {
            retry_intent(format!("send_bootstrap_connection_request tcp send: {err}"))
        })?;
        Ok(HandlerOutput::new())
    }
}

fn send_bootstrap_connection_request_key(input: &SendBootstrapConnectionRequest) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:send-bootstrap-connection-request:v1:");
    hash.update(&input.request_id);
    hash.update(input.addr.to_string().as_bytes());
    hash.finalize().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use crate::core::crypto::{self, ED25519_SIGNATURE_BYTES};
    use crate::core::facts::{Fact, FactScope};
    use crate::core::handler_dispatch::{retry_intent_reason, HandlerContext, IntentHandler};
    use crate::core::network_queues;
    use crate::core::schema_dsl::{CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE, INTENTS_SCHEMA_SOURCE};
    use crate::core::store::Store;
    use crate::protocol::facts::connection::request::fact::ConnectionRequestFact;

    use super::*;

    #[test]
    fn unreachable_bootstrap_peer_requests_retry_without_consuming_intent() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind closed listener");
        let addr = listener.local_addr().expect("listener addr");
        drop(listener);

        let store = Store::open_memory_with_schema_sources_and_schemas(
            &[
                CORE_SCHEMA_SOURCE,
                FACTS_SCHEMA_SOURCE,
                INTENTS_SCHEMA_SOURCE,
            ],
            network_queues::SCHEMAS,
        )
        .expect("store");
        let request_fact = request_fact();
        let intent = send_bootstrap_connection_request_intent(SendBootstrapConnectionRequest {
            request_id: request_fact.id,
            addr,
        })
        .expect("intent");

        let err = SendBootstrapConnectionRequestHandler::new()
            .handle(
                &intent,
                &HandlerContext::with_facts([request_fact]).with_store(&store),
            )
            .expect_err("unreachable bootstrap peer should request retry");

        assert!(retry_intent_reason(&err).is_some(), "{err}");
        assert!(err.contains("open tcp stream"), "{err}");
    }

    fn request_fact() -> Fact {
        let invite_secret = [31; 32];
        let ephemeral_secret = [32; 32];
        let request = ConnectionRequestFact {
            from_endpoint: crypto::x25519_public_key(&invite_secret),
            to_endpoint: [11; 32],
            nonce: [12; 32],
            invite_fact_id: [13; 32],
            bootstrap_hash: [14; 32],
            invite_signature: [15; ED25519_SIGNATURE_BYTES],
            invite_secret_fact_id: [16; 32],
            initiator_ephemeral_secret_fact_id: [17; 32],
            initiator_ephemeral_public_key: crypto::x25519_public_key(&ephemeral_secret),
            from_listen_addr: None,
            to_listen_addr: None,
        };
        Fact::new(
            FactScope::Global,
            1,
            layout::encode_fact(&request).expect("request"),
        )
    }
}
