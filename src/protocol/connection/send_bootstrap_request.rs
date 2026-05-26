//! Bootstrap request network-send intent.
//!
//! Before a connection exists, the only outbound network operation is sending a
//! sealed `connection::request` fact to the invite link's socket address. The
//! request projector emits this local intent after it has materialized the
//! request row; the handler loads exactly that request fact plus its initiator
//! ephemeral secret, resolves the explicit socket address from the intent
//! payload, stages sealed bytes in core networking, and attempts one bounded
//! write.
//!
//! The intent key is `(request_id, initiator_ephemeral_secret_id, addr)`, so
//! duplicate attempts are idempotent for the same bootstrap target. Retry timing
//! is owned by the request projector's peer-retry time wake. Change this file
//! for pre-connection send payload behavior. Established connection frames use
//! `send_network_frame`.

use std::net::SocketAddr;

use crate::core::effects::PipelineEffects;
use crate::core::intents::{HandlerContext, HandlerFactId, HandlerResult, IntentHandler};
use crate::core::intents::{Intent, IntentKind};
use crate::core::network::{self, NetworkTarget, OutboundFrame};
use crate::protocol::connection::request::create as addr;
use crate::protocol::connection::request::layout;

pub const SEND_BOOTSTRAP_CONNECTION_REQUEST: &str = "send_bootstrap_connection_request";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SendBootstrapConnectionRequest {
    pub request_id: [u8; 32],
    pub initiator_ephemeral_secret_id: [u8; 32],
    pub addr: SocketAddr,
}

pub fn send_bootstrap_connection_request_intent(
    input: SendBootstrapConnectionRequest,
) -> Result<Intent, String> {
    let mut payload = Vec::with_capacity(1 + 32 + 32 + addr::ADDR_BLOCK_BYTES);
    payload.push(1);
    payload.extend_from_slice(&input.request_id);
    payload.extend_from_slice(&input.initiator_ephemeral_secret_id);
    payload.extend_from_slice(&addr::encode_optional_addr(Some(input.addr))?);
    Ok(Intent::new(
        IntentKind::new(SEND_BOOTSTRAP_CONNECTION_REQUEST)
            .expect("valid send bootstrap connection request intent kind"),
        send_bootstrap_connection_request_key(&input),
        payload,
    ))
}

pub fn decode_send_bootstrap_connection_request(
    intent: &Intent,
) -> Result<SendBootstrapConnectionRequest, String> {
    if intent.kind.as_str() != SEND_BOOTSTRAP_CONNECTION_REQUEST {
        return Err("expected send_bootstrap_connection_request intent".into());
    }
    if intent.payload.len() != 1 + 32 + 32 + addr::ADDR_BLOCK_BYTES {
        return Err("send_bootstrap_connection_request payload has wrong length".into());
    }
    if intent.payload[0] != 1 {
        return Err("send_bootstrap_connection_request payload version unsupported".into());
    }
    let request_id = intent.payload[1..33].try_into().unwrap();
    let initiator_ephemeral_secret_id = intent.payload[33..65].try_into().unwrap();
    let mut addr_bytes = [0; addr::ADDR_BLOCK_BYTES];
    addr_bytes.copy_from_slice(&intent.payload[65..]);
    let addr = addr::decode_optional_addr(&addr_bytes)?
        .ok_or_else(|| "send_bootstrap_connection_request addr is missing".to_string())?;
    let input = SendBootstrapConnectionRequest {
        request_id,
        initiator_ephemeral_secret_id,
        addr,
    };
    if intent.key != send_bootstrap_connection_request_key(&input) {
        return Err("send_bootstrap_connection_request key does not match payload".into());
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
    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_send_bootstrap_connection_request(intent)?;
        Ok(vec![input.request_id, input.initiator_ephemeral_secret_id])
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_send_bootstrap_connection_request(intent)?;
        let request_fact = context.require_fact(&input.request_id)?;
        let request = layout::decode_fact(request_fact.body())?;
        if request.initiator_ephemeral_secret_fact_id != input.initiator_ephemeral_secret_id {
            return Err(
                "send_bootstrap_connection_request ephemeral id does not match request".into(),
            );
        }
        let ephemeral_fact = context.require_fact(&input.initiator_ephemeral_secret_id)?;
        let ephemeral = crate::protocol::connection::ephemeral_secret::layout::decode_fact(
            ephemeral_fact.body(),
        )?;
        if ephemeral.owner_endpoint != request.from_endpoint {
            return Err(
                "send_bootstrap_connection_request ephemeral owner does not match request".into(),
            );
        }
        if ephemeral.ephemeral_public_key != request.initiator_ephemeral_public_key {
            return Err(
                "send_bootstrap_connection_request ephemeral public key does not match request"
                    .into(),
            );
        }
        let sealed = crate::protocol::connection::bootstrap_request::seal_connection_request(
            request_fact.body(),
            &ephemeral.ephemeral_private_key,
        )?;
        let target = NetworkTarget::new(input.addr);
        if network::send(context.store()?, target, OutboundFrame { bytes: sealed }).is_err() {
            return Ok(PipelineEffects::new());
        }
        Ok(PipelineEffects::new())
    }
}

fn send_bootstrap_connection_request_key(input: &SendBootstrapConnectionRequest) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:send-bootstrap-connection-request:v1:");
    hash.update(&input.request_id);
    hash.update(&input.initiator_ephemeral_secret_id);
    hash.update(input.addr.to_string().as_bytes());
    hash.finalize().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::net::TcpListener;
    use std::thread;

    use super::*;
    use crate::core::crypto::{self, ED25519_SIGNATURE_BYTES};
    use crate::core::facts::{Fact, FactScope};
    use crate::core::intents::IntentHandler;
    use crate::core::schema::CORE_SCHEMA_SOURCE;
    use crate::core::store::Store;
    use crate::protocol::auth::endpoint::fact::EndpointFact;
    use crate::protocol::connection::bootstrap_request;
    use crate::protocol::connection::ephemeral_secret::{
        fact::ConnectionEphemeralSecretFact, layout as ephemeral_layout,
    };
    use crate::protocol::connection::request::fact::ConnectionRequestFact;
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;

    #[test]
    fn sends_sealed_bootstrap_request_bytes() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let addr = listener.local_addr().expect("listener addr");
        let reader = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut len = [0u8; 4];
            stream.read_exact(&mut len).expect("read len");
            let mut body = vec![0; u32::from_be_bytes(len) as usize];
            stream.read_exact(&mut body).expect("read body");
            body
        });

        let responder_secret = [21; 32];
        let initiator_ephemeral_private_key = [18; 32];
        let (request_fact, ephemeral_fact) =
            request_and_ephemeral(addr, responder_secret, initiator_ephemeral_private_key);
        let intent = send_bootstrap_connection_request_intent(SendBootstrapConnectionRequest {
            request_id: request_fact.id,
            initiator_ephemeral_secret_id: ephemeral_fact.id,
            addr,
        })
        .expect("intent");
        let store = Store::open_memory_with_schema_sources(&[
            CORE_SCHEMA_SOURCE,
            network::SCHEMA_SOURCE,
            FACTS_SCHEMA_SOURCE,
        ])
        .expect("store");

        SendBootstrapConnectionRequestHandler::new()
            .handle(
                &intent,
                &HandlerContext::with_facts([request_fact.clone(), ephemeral_fact])
                    .with_store(&store),
            )
            .expect("send sealed request");

        let sent = reader.join().expect("reader");
        assert_eq!(sent[0], bootstrap_request::TYPE_SEALED_CONNECTION_REQUEST);
        assert_ne!(sent, request_fact.bytes);
        let responder = EndpointFact {
            endpoint: crypto::x25519_public_key(&responder_secret),
            secret: responder_secret,
            signing_public_key: crypto::ed25519_public_key(&[31; 32]),
            signing_secret: [31; 32],
        };
        assert_eq!(
            bootstrap_request::open_connection_request(&sent, &responder).expect("open request"),
            request_fact.bytes
        );
    }

    #[test]
    fn unreachable_bootstrap_peer_consumes_attempt_for_projected_retry() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind closed listener");
        let addr = listener.local_addr().expect("listener addr");
        drop(listener);

        let (request_fact, ephemeral_fact) = request_and_ephemeral(addr, [11; 32], [18; 32]);
        let intent = send_bootstrap_connection_request_intent(SendBootstrapConnectionRequest {
            request_id: request_fact.id,
            initiator_ephemeral_secret_id: ephemeral_fact.id,
            addr,
        })
        .expect("intent");
        let store = Store::open_memory_with_schema_sources(&[
            CORE_SCHEMA_SOURCE,
            network::SCHEMA_SOURCE,
            FACTS_SCHEMA_SOURCE,
        ])
        .expect("store");

        SendBootstrapConnectionRequestHandler::new()
            .handle(
                &intent,
                &HandlerContext::with_facts([request_fact, ephemeral_fact]).with_store(&store),
            )
            .expect("unreachable peer attempt is consumed");
    }

    fn request_and_ephemeral(
        addr: std::net::SocketAddr,
        responder_secret: [u8; 32],
        initiator_ephemeral_private_key: [u8; 32],
    ) -> (Fact, Fact) {
        let ephemeral = ConnectionEphemeralSecretFact {
            owner_endpoint: [10; 32],
            ephemeral_private_key: initiator_ephemeral_private_key,
            ephemeral_public_key: crypto::x25519_public_key(&initiator_ephemeral_private_key),
            created_at_ms: 1,
        };
        let ephemeral_fact = Fact::new(
            FactScope::Local,
            1,
            ephemeral_layout::encode_fact(&ephemeral).expect("ephemeral"),
        );
        let request = ConnectionRequestFact {
            from_endpoint: ephemeral.owner_endpoint,
            to_endpoint: crypto::x25519_public_key(&responder_secret),
            nonce: [12; 32],
            invite_fact_id: [13; 32],
            bootstrap_hash: [14; 32],
            invite_signature: [15; ED25519_SIGNATURE_BYTES],
            invite_secret_fact_id: [16; 32],
            initiator_ephemeral_secret_fact_id: ephemeral_fact.id,
            initiator_ephemeral_public_key: ephemeral.ephemeral_public_key,
            from_listen_addr: Some(addr),
            to_listen_addr: None,
        };
        let request_fact = Fact::new(
            FactScope::Global,
            1,
            layout::encode_fact(&request).expect("request"),
        );
        (request_fact, ephemeral_fact)
    }
}
