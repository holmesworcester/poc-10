//! Responder-side connection-authoring intent.
//!
//! A validated inbound connection request does not create its connection inline
//! during request projection. The request projector emits this intent with the
//! request, authority, and receive-receipt fact ids. The authority id is an
//! invite secret in bootstrap mode or endpoint_shared in membership mode.
//!
//! The payload is three fixed 32-byte ids in order: request id, initiator
//! endpoint_shared id, and fact-receipt id.

use crate::core::effects::PipelineEffects;
use crate::core::intents::{Intent, IntentKind};

pub type FactId = [u8; 32];

pub const CREATE_CONNECTION: &str = "create_connection";

const FIELD_BYTES: usize = 32;
const FIELD_COUNT: usize = 3;
const PAYLOAD_BYTES: usize = FIELD_BYTES * FIELD_COUNT;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateConnection {
    pub request_id: FactId,
    /// Invite secret for bootstrap requests, endpoint_shared for membership
    /// requests. Kept under the old field name for payload compatibility.
    pub initiator_endpoint_shared_id: FactId,
    pub receive_id: FactId,
}

pub fn create_connection_intent(input: CreateConnection) -> Intent {
    let payload = encode_payload(&input);
    let key = idempotence_key(&input);
    Intent::new(
        IntentKind::new(CREATE_CONNECTION).expect("valid create connection intent kind"),
        key,
        payload,
    )
}

pub fn decode_create_connection_intent(intent: &Intent) -> Result<CreateConnection, String> {
    if intent.kind.as_str() != CREATE_CONNECTION {
        return Err("expected create_connection intent".into());
    }
    if intent.payload.len() != PAYLOAD_BYTES {
        return Err("create_connection payload has wrong length".into());
    }
    let input = CreateConnection {
        request_id: take_id(&intent.payload, 0),
        initiator_endpoint_shared_id: take_id(&intent.payload, 1),
        receive_id: take_id(&intent.payload, 2),
    };
    if intent.key != idempotence_key(&input) {
        return Err("create_connection idempotence key does not match payload".into());
    }
    Ok(input)
}

fn encode_payload(input: &CreateConnection) -> Vec<u8> {
    let mut out = vec![0u8; PAYLOAD_BYTES];
    out[0..32].copy_from_slice(&input.request_id);
    out[32..64].copy_from_slice(&input.initiator_endpoint_shared_id);
    out[64..96].copy_from_slice(&input.receive_id);
    out
}

fn idempotence_key(input: &CreateConnection) -> Vec<u8> {
    // The request fact id is the connection-authoring unit of work; duplicate
    // deliveries may produce different receipt fact ids, but only one
    // connection is authored per request.
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo:create-connection-intent:v1:");
    hasher.update(&input.request_id);
    hasher.finalize().as_bytes().to_vec()
}

fn take_id(payload: &[u8], index: usize) -> FactId {
    let start = index * FIELD_BYTES;
    let mut out = [0u8; 32];
    out.copy_from_slice(&payload[start..start + FIELD_BYTES]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CreateConnection {
        CreateConnection {
            request_id: [1; 32],
            initiator_endpoint_shared_id: [2; 32],
            receive_id: [3; 32],
        }
    }

    #[test]
    fn intent_roundtrips() {
        let intent = create_connection_intent(sample());
        let decoded = decode_create_connection_intent(&intent).expect("decode");
        assert_eq!(decoded, sample());
    }

    #[test]
    fn rejects_tampered_payload() {
        let mut intent = create_connection_intent(sample());
        intent.payload[0] ^= 0xff;
        assert!(decode_create_connection_intent(&intent).is_err());
    }

    #[test]
    fn idempotence_key_is_request_scoped() {
        let mut duplicate_receive = sample();
        duplicate_receive.receive_id = [9; 32];
        assert_eq!(
            create_connection_intent(sample()).key,
            create_connection_intent(duplicate_receive).key
        );
    }
}

// The handler proves the queued dependency ids still name the expected facts,
// then delegates DH handshake construction to `connection::create`.

use crate::core::facts::FactScope;
use crate::core::intents::{
    HandlerContext, HandlerError, HandlerFactId, HandlerResult, IntentHandler,
};
use crate::protocol::auth::endpoint::author as local_endpoint;
use crate::protocol::auth::endpoint_shared;
use crate::protocol::connection::connection::author::{
    build_responder_connection, BuildResponderConnection,
};
use crate::protocol::connection::ephemeral_secret::author as ephemeral_author;
use crate::protocol::connection::fact_receipt;
use crate::protocol::connection::request::authenticate as request_auth;
use crate::protocol::connection::request::decode as request_layout;
use crate::protocol::connection::request::fact::{REQUEST_MODE_BOOTSTRAP, REQUEST_MODE_MEMBERSHIP};
use std::net::SocketAddr;

#[derive(Debug, Clone, Default)]
pub struct CreateConnectionHandler;

impl CreateConnectionHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for CreateConnectionHandler {
    fn input_fact_ids(&self, raw_intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_create_connection_intent(raw_intent)?;
        Ok(vec![
            input.request_id,
            input.initiator_endpoint_shared_id,
            input.receive_id,
        ])
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_create_connection_intent(intent)?;
        let request_fact = context.require_fact(&input.request_id)?;
        let authority_fact = context.require_fact(&input.initiator_endpoint_shared_id)?;
        let receive_fact = context.require_fact(&input.receive_id)?;

        let endpoint = local_endpoint::local_endpoint(context.store()?)?.ok_or_else(|| {
            HandlerError::fatal("create_connection requires local endpoint state")
        })?;
        let request = request_layout::open_fact(request_fact.body(), &endpoint)?;
        let received = fact_receipt::decode_fact_payload(receive_fact.body()).map_err(|_| {
            HandlerError::fatal("create_connection receive context is not connection fact receipt")
        })?;
        if receive_fact.scope != FactScope::Local {
            return Err("create_connection receive context must be local".into());
        }
        validate_fact_receipt(input.request_id, &request, &received)?;

        if endpoint.endpoint != request.to_endpoint
            || endpoint.endpoint != received.local_endpoint_id
        {
            return Err("create_connection endpoint does not match request".into());
        }
        let invite = match request.mode {
            REQUEST_MODE_BOOTSTRAP => {
                if authority_fact.id != request.invite_secret_fact_id {
                    return Err("create_connection invite id does not match request".into());
                }
                if authority_fact.scope != FactScope::Local {
                    return Err("create_connection invite context must be local".into());
                }
                let invite = request_auth::invite_secret_from_context_fact(
                    authority_fact,
                    request.invite_secret_fact_id,
                )
                .map_err(|_| {
                    HandlerError::fatal("create_connection context is not invite secret")
                })?;
                request_auth::validate_invite_signature(&request, &invite)?;
                Some(invite)
            }
            REQUEST_MODE_MEMBERSHIP => {
                if authority_fact.id != request.initiator_endpoint_shared_id {
                    return Err(
                        "create_connection endpoint_shared id does not match request".into(),
                    );
                }
                if authority_fact.scope != FactScope::Global {
                    return Err("create_connection endpoint_shared context must be global".into());
                }
                let initiator_shared = endpoint_shared::decode_fact_payload(authority_fact.body())
                    .map_err(|_| {
                        HandlerError::fatal("create_connection context is not endpoint_shared")
                    })?;
                if initiator_shared.endpoint_id != request.from_endpoint {
                    return Err("create_connection endpoint_shared does not bind the sender".into());
                }
                request_auth::validate_endpoint_signature(
                    &request,
                    &initiator_shared.signing_public_key,
                )?;
                None
            }
            other => return Err(format!("create_connection unknown request mode {other}").into()),
        };
        let responder_addr = request.dialed_addr;
        let initiator_addr = request
            .initiator_addr
            .or(Some(parse_origin_addr(&received)?));

        let (responder_ephemeral, responder_ephemeral_fact) =
            ephemeral_author::random_secret_fact(endpoint.endpoint, received.received_at_local_ms)?;
        let responder_ephemeral_private_key = responder_ephemeral.ephemeral_private_key;

        let built = build_responder_connection(BuildResponderConnection {
            request_id: input.request_id,
            request: &request,
            invite: invite.as_ref(),
            endpoint: &endpoint,
            responder_ephemeral_private_key,
            responder_ephemeral_secret_fact_id: responder_ephemeral_fact.id,
            responder_addr,
            initiator_addr,
            created_at_ms: received.received_at_local_ms,
        })?;

        Ok(PipelineEffects::new()
            .fact(responder_ephemeral_fact)
            .fact(built.fact))
    }
}

fn parse_origin_addr(
    received: &fact_receipt::fact::ConnectionFactReceipt,
) -> Result<SocketAddr, String> {
    received
        .origin_addr_str()
        .map_err(|_| "create_connection origin address is not utf-8".to_string())?
        .parse()
        .map_err(|_| "create_connection origin address is not a socket address".to_string())
}

fn validate_fact_receipt(
    request_id: [u8; 32],
    request: &crate::protocol::connection::request::fact::ConnectionRequestFact,
    received: &fact_receipt::fact::ConnectionFactReceipt,
) -> Result<(), String> {
    if received.received_fact_id != request_id {
        return Err("create_connection receive context targets another fact".into());
    }
    if received.receive_path != fact_receipt::fact::RECEIVE_PATH_CONNECTION_REQUEST {
        return Err("create_connection requires connection request receipt".into());
    }
    if received.local_endpoint_id != request.to_endpoint {
        return Err("create_connection request endpoint does not match receive".into());
    }
    if received.sender_endpoint_id != request.from_endpoint {
        return Err("create_connection sender does not match receive".into());
    }
    if received.request_id != Some(request_id) {
        return Err("create_connection fact receipt names another request".into());
    }
    Ok(())
}
