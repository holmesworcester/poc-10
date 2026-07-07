//! Responder-side membership connection-response intent.
//!
//! A validated inbound membership request does not create its response inline
//! during request projection. The request projector emits this intent with the
//! request, initiator endpoint_shared, and receive-receipt fact ids; the handler
//! loads exactly those facts, re-verifies the initiator endpoint signature
//! against its membership signing key, creates fresh responder ephemeral
//! material, and builds the canonical local `connection_response` fact. The send
//! itself is not done here: the flat-intent rule keeps this handler to fact
//! creation, and the local `connection_response` projector emits the send once
//! the response fact is admitted.
//!
//! The payload is three fixed 32-byte ids in order: request id, initiator
//! endpoint_shared id, and fact-receipt id.

use crate::core::effects::PipelineEffects;
use crate::core::intents::{Intent, IntentKind};

pub type FactId = [u8; 32];

pub const CREATE_CONNECTION_RESPONSE: &str = "create_connection_response";

const FIELD_BYTES: usize = 32;
const FIELD_COUNT: usize = 3;
const PAYLOAD_BYTES: usize = FIELD_BYTES * FIELD_COUNT;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateConnectionResponse {
    pub request_id: FactId,
    pub initiator_endpoint_shared_id: FactId,
    pub receive_id: FactId,
}

pub fn create_connection_response_intent(input: CreateConnectionResponse) -> Intent {
    let payload = encode_payload(&input);
    let key = idempotence_key(&input);
    Intent::new(
        IntentKind::new(CREATE_CONNECTION_RESPONSE)
            .expect("valid create connection response intent kind"),
        key,
        payload,
    )
}

pub fn decode_create_connection_response_intent(
    intent: &Intent,
) -> Result<CreateConnectionResponse, String> {
    if intent.kind.as_str() != CREATE_CONNECTION_RESPONSE {
        return Err("expected create_connection_response intent".into());
    }
    if intent.payload.len() != PAYLOAD_BYTES {
        return Err("create_connection_response payload has wrong length".into());
    }
    let input = CreateConnectionResponse {
        request_id: take_id(&intent.payload, 0),
        initiator_endpoint_shared_id: take_id(&intent.payload, 1),
        receive_id: take_id(&intent.payload, 2),
    };
    if intent.key != idempotence_key(&input) {
        return Err("create_connection_response idempotence key does not match payload".into());
    }
    Ok(input)
}

fn encode_payload(input: &CreateConnectionResponse) -> Vec<u8> {
    let mut out = vec![0u8; PAYLOAD_BYTES];
    out[0..32].copy_from_slice(&input.request_id);
    out[32..64].copy_from_slice(&input.initiator_endpoint_shared_id);
    out[64..96].copy_from_slice(&input.receive_id);
    out
}

fn idempotence_key(input: &CreateConnectionResponse) -> Vec<u8> {
    // The request fact id is the response unit of work; duplicate deliveries may
    // produce different receipt fact ids, but only one response per request.
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo:create-membership-connection-response-intent:v1:");
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

    fn sample() -> CreateConnectionResponse {
        CreateConnectionResponse {
            request_id: [1; 32],
            initiator_endpoint_shared_id: [2; 32],
            receive_id: [3; 32],
        }
    }

    #[test]
    fn intent_roundtrips() {
        let intent = create_connection_response_intent(sample());
        let decoded = decode_create_connection_response_intent(&intent).expect("decode");
        assert_eq!(decoded, sample());
    }

    #[test]
    fn rejects_tampered_payload() {
        let mut intent = create_connection_response_intent(sample());
        intent.payload[0] ^= 0xff;
        assert!(decode_create_connection_response_intent(&intent).is_err());
    }

    #[test]
    fn idempotence_key_is_request_scoped() {
        let mut duplicate_receive = sample();
        duplicate_receive.receive_id = [9; 32];
        assert_eq!(
            create_connection_response_intent(sample()).key,
            create_connection_response_intent(duplicate_receive).key
        );
    }
}

// The handler proves the queued dependency ids still name the expected facts and
// re-verifies membership, then delegates DH handshake construction to
// `connection_response::create`.

use crate::core::crypto;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::{
    HandlerContext, HandlerError, HandlerFactId, HandlerResult, IntentHandler,
};
use crate::protocol::auth::endpoint::create as local_endpoint;
use crate::protocol::auth::endpoint_shared;
use crate::protocol::connection::connection_request::decode as request_layout;
use crate::protocol::connection::connection_request::encode as request_create;
use crate::protocol::connection::connection_response::create::{
    build_responder_response, BuildResponderResponse,
};
use crate::protocol::connection::ephemeral_secret::{
    fact::ConnectionEphemeralSecretFact, layout as ephemeral_layout,
};
use crate::protocol::connection::fact_receipt;

#[derive(Debug, Clone, Default)]
pub struct CreateConnectionResponseHandler;

impl CreateConnectionResponseHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for CreateConnectionResponseHandler {
    fn input_fact_ids(&self, raw_intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_create_connection_response_intent(raw_intent)?;
        Ok(vec![
            input.request_id,
            input.initiator_endpoint_shared_id,
            input.receive_id,
        ])
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_create_connection_response_intent(intent)?;
        let request_fact = context.require_fact(&input.request_id)?;
        let shared_fact = context.require_fact(&input.initiator_endpoint_shared_id)?;
        let receive_fact = context.require_fact(&input.receive_id)?;

        let request = request_layout::decode_fact(request_fact.body())?;
        let initiator_shared =
            endpoint_shared::decode_fact_payload(shared_fact.body()).map_err(|_| {
                HandlerError::fatal("create_connection_response context is not endpoint_shared")
            })?;
        let received = fact_receipt::decode_fact_payload(receive_fact.body()).map_err(|_| {
            HandlerError::fatal(
                "create_connection_response receive context is not connection fact receipt",
            )
        })?;

        if request.initiator_endpoint_shared_id != input.initiator_endpoint_shared_id {
            return Err(
                "create_connection_response endpoint_shared id does not match request".into(),
            );
        }
        if shared_fact.scope != FactScope::Global {
            return Err("create_connection_response endpoint_shared context must be global".into());
        }
        if initiator_shared.endpoint_id != request.from_endpoint {
            return Err(
                "create_connection_response endpoint_shared does not bind the sender".into(),
            );
        }
        if receive_fact.scope != FactScope::Local {
            return Err("create_connection_response receive context must be local".into());
        }
        request_create::validate_endpoint_signature(
            &request,
            &initiator_shared.signing_public_key,
        )?;
        validate_fact_receipt(input.request_id, &request, &received)?;

        let endpoint = local_endpoint::local_endpoint(context.store()?)?.ok_or_else(|| {
            HandlerError::fatal("create_connection_response requires local endpoint state")
        })?;
        if endpoint.endpoint != request.to_endpoint
            || endpoint.endpoint != received.local_endpoint_id
        {
            return Err("create_connection_response endpoint does not match request".into());
        }
        if request.from_listen_addr.is_none() {
            return Err("create_connection_response response route is missing".into());
        }

        let responder_ephemeral_private_key = crypto::random_x25519_private_key();
        let responder_ephemeral = ConnectionEphemeralSecretFact {
            owner_endpoint: endpoint.endpoint,
            ephemeral_private_key: responder_ephemeral_private_key,
            ephemeral_public_key: crypto::x25519_public_key(&responder_ephemeral_private_key),
            created_at_ms: received.received_at_local_ms,
        };
        let responder_ephemeral_fact = Fact::new(
            FactScope::Local,
            received.received_at_local_ms,
            ephemeral_layout::encode_fact(&responder_ephemeral)?,
        );

        let built = build_responder_response(BuildResponderResponse {
            request_id: input.request_id,
            request: &request,
            endpoint: &endpoint,
            responder_ephemeral_private_key,
            responder_ephemeral_secret_fact_id: responder_ephemeral_fact.id,
            created_at_ms: received.received_at_local_ms,
        })?;

        Ok(PipelineEffects::new()
            .fact(responder_ephemeral_fact)
            .fact(built.fact))
    }
}

fn validate_fact_receipt(
    request_id: [u8; 32],
    request: &crate::protocol::connection::connection_request::fact::ConnectionRequestFact,
    received: &fact_receipt::fact::ConnectionFactReceipt,
) -> Result<(), String> {
    if received.received_fact_id != request_id {
        return Err("create_connection_response receive context targets another fact".into());
    }
    if received.receive_path != fact_receipt::fact::RECEIVE_PATH_CONNECTION_REQUEST {
        return Err("create_connection_response requires connection request receipt".into());
    }
    if received.local_endpoint_id != request.to_endpoint {
        return Err("create_connection_response request endpoint does not match receive".into());
    }
    if received.sender_endpoint_id != request.from_endpoint {
        return Err("create_connection_response sender does not match receive".into());
    }
    if received.request_id != Some(request_id) {
        return Err("create_connection_response fact receipt names another request".into());
    }
    Ok(())
}
