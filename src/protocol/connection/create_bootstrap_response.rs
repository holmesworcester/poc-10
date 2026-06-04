//! Responder-side connection-response intent.
//!
//! A validated inbound request does not create its response inline during
//! request projection. The request projector emits this intent with the
//! request, invite-secret, and receive-receipt fact ids; the handler loads
//! exactly those facts, creates fresh responder ephemeral material, builds the
//! canonical response body, and emits local `bootstrap_response_sent` plus
//! `connection_established` facts through the normal pipeline.
//!
//! The payload is three fixed 32-byte ids in order: request id, invite-secret
//! id, and fact-receipt id. This file owns intent identity, idempotence,
//! input-fact declaration, and bounded handler orchestration. The native
//! handshake schedule lives in `bootstrap_response::create`; request and receipt
//! admission live in their projectors.

use crate::core::effects::PipelineEffects;
use crate::core::intents::{Intent, IntentKind};

/// 32-byte fact id, named locally to avoid pulling fact module types into
/// the handler intent file.
pub type FactId = [u8; 32];

pub const CREATE_BOOTSTRAP_RESPONSE: &str = "create_bootstrap_response";

const FIELD_BYTES: usize = 32;
const FIELD_COUNT: usize = 3;
const PAYLOAD_BYTES: usize = FIELD_BYTES * FIELD_COUNT;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateBootstrapResponse {
    pub request_id: FactId,
    pub invite_secret_id: FactId,
    pub receive_id: FactId,
}

pub fn create_bootstrap_response_intent(input: CreateBootstrapResponse) -> Intent {
    let payload = encode_payload(&input);
    let key = idempotence_key(&input);
    Intent::new(
        IntentKind::new(CREATE_BOOTSTRAP_RESPONSE)
            .expect("valid create connection response intent kind"),
        key,
        payload,
    )
}

pub fn decode_create_bootstrap_response_intent(
    intent: &Intent,
) -> Result<CreateBootstrapResponse, String> {
    if intent.kind.as_str() != CREATE_BOOTSTRAP_RESPONSE {
        return Err("expected create_bootstrap_response intent".into());
    }
    if intent.payload.len() != PAYLOAD_BYTES {
        return Err("create_bootstrap_response payload has wrong length".into());
    }
    let input = CreateBootstrapResponse {
        request_id: take_id(&intent.payload, 0),
        invite_secret_id: take_id(&intent.payload, 1),
        receive_id: take_id(&intent.payload, 2),
    };
    if intent.key != idempotence_key(&input) {
        return Err("create_bootstrap_response idempotence key does not match payload".into());
    }
    Ok(input)
}

fn encode_payload(input: &CreateBootstrapResponse) -> Vec<u8> {
    let mut out = vec![0u8; PAYLOAD_BYTES];
    out[0..32].copy_from_slice(&input.request_id);
    out[32..64].copy_from_slice(&input.invite_secret_id);
    out[64..96].copy_from_slice(&input.receive_id);
    out
}

fn idempotence_key(input: &CreateBootstrapResponse) -> Vec<u8> {
    // The request fact id is the bootstrap-response unit of work. Duplicate
    // deliveries may produce different receipt fact ids, but only one
    // response should be created for a request.
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo:create-connection-response-intent:v1:");
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

    fn sample() -> CreateBootstrapResponse {
        CreateBootstrapResponse {
            request_id: [1; 32],
            invite_secret_id: [2; 32],
            receive_id: [3; 32],
        }
    }

    #[test]
    fn intent_roundtrips() {
        let intent = create_bootstrap_response_intent(sample());
        let decoded = decode_create_bootstrap_response_intent(&intent).expect("decode");
        assert_eq!(decoded, sample());
    }

    #[test]
    fn rejects_wrong_kind() {
        let mut intent = create_bootstrap_response_intent(sample());
        intent.kind = IntentKind::new("not_connection_response").unwrap();
        assert!(decode_create_bootstrap_response_intent(&intent).is_err());
    }

    #[test]
    fn rejects_tampered_payload() {
        let mut intent = create_bootstrap_response_intent(sample());
        intent.payload[0] ^= 0xff;
        assert!(decode_create_bootstrap_response_intent(&intent).is_err());
    }

    #[test]
    fn rejects_tampered_key() {
        let mut intent = create_bootstrap_response_intent(sample());
        intent.key[0] ^= 0xff;
        assert!(decode_create_bootstrap_response_intent(&intent).is_err());
    }

    #[test]
    fn idempotence_key_is_request_scoped() {
        let mut duplicate_receive = sample();
        duplicate_receive.receive_id = [9; 32];

        assert_eq!(
            create_bootstrap_response_intent(sample()).key,
            create_bootstrap_response_intent(duplicate_receive).key
        );
    }
}

// The handler stays at the orchestration boundary: it proves that the queued
// dependency ids still name the expected facts, then delegates native handshake
// construction to `response::create`.

use crate::core::crypto;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::{
    HandlerContext, HandlerError, HandlerFactId, HandlerResult, IntentHandler,
};
use crate::protocol::auth::endpoint::create as local_endpoint;
use crate::protocol::auth::invite::layout as invite_layout;
use crate::protocol::connection::bootstrap_request::create as request_create;
use crate::protocol::connection::bootstrap_request::layout as request_layout;
use crate::protocol::connection::bootstrap_response::create::{
    build_responder_response, BuildResponderResponse,
};
use crate::protocol::connection::bootstrap_response::transit as response_transit;
use crate::protocol::connection::bootstrap_response_sent::{
    fact::BootstrapResponseSentFact, layout as response_sent_layout,
};
use crate::protocol::connection::connection_established::{
    fact::ConnectionEstablishedFact, layout as established_layout,
};
use crate::protocol::connection::ephemeral_secret::{
    fact::ConnectionEphemeralSecretFact, layout as ephemeral_layout,
};
use crate::protocol::connection::fact_receipt;

#[derive(Debug, Clone, Default)]
pub struct CreateBootstrapResponseHandler;

impl CreateBootstrapResponseHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for CreateBootstrapResponseHandler {
    fn input_fact_ids(&self, raw_intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_create_bootstrap_response_intent(raw_intent)?;
        Ok(vec![
            input.request_id,
            input.invite_secret_id,
            input.receive_id,
        ])
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_create_bootstrap_response_intent(intent)?;
        let request_fact = context.require_fact(&input.request_id)?;
        let invite_fact = context.require_fact(&input.invite_secret_id)?;
        let receive_fact = context.require_fact(&input.receive_id)?;

        let request = request_layout::decode_fact(request_fact.body())?;
        let invite = invite_layout::decode_fact(&invite_fact.bytes)?;
        let received = fact_receipt::decode_fact_payload(receive_fact.body()).map_err(|_| {
            HandlerError::fatal(
                "create_bootstrap_response receive context is not connection fact receipt",
            )
        })?;

        if request.invite_secret_fact_id != input.invite_secret_id {
            return Err(
                "create_bootstrap_response invite context id does not match request".into(),
            );
        }
        if invite_fact.scope != FactScope::Local {
            return Err("create_bootstrap_response invite context must be local".into());
        }
        if receive_fact.scope != FactScope::Local {
            return Err("create_bootstrap_response receive context must be local".into());
        }
        request_create::validate_invite_signature(&request, &invite)?;
        validate_fact_receipt(input.request_id, &request, &received)?;
        let endpoint = local_endpoint::local_endpoint(context.store()?)?.ok_or_else(|| {
            HandlerError::fatal("create_bootstrap_response requires local endpoint state")
        })?;
        if endpoint.endpoint != request.to_endpoint
            || endpoint.endpoint != received.local_endpoint_id
        {
            return Err("create_bootstrap_response endpoint does not match request".into());
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
            invite: &invite,
            endpoint: &endpoint,
            responder_ephemeral_private_key,
            responder_ephemeral_secret_fact_id: responder_ephemeral_fact.id,
            created_at_ms: received.received_at_local_ms,
        })?;
        let sealed_response_bytes = response_transit::seal_connection_response(
            built.fact.body(),
            &responder_ephemeral_private_key,
        )?;
        let sealed_response_bytes = sealed_response_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "sealed bootstrap response has unexpected byte length".to_string())?;
        let peer_addr = request
            .from_listen_addr
            .ok_or_else(|| "create_bootstrap_response response route is missing".to_string())?;
        let response_sent = BootstrapResponseSentFact {
            response_id: built.fact.id,
            request_id: input.request_id,
            responder_ephemeral_secret_fact_id: responder_ephemeral_fact.id,
            peer_addr,
            response: built.response,
            sealed_response_bytes,
            created_at_ms: received.received_at_local_ms,
        };
        let response_sent_fact = Fact::new(
            FactScope::Local,
            received.received_at_local_ms,
            response_sent_layout::encode_fact(&response_sent)?,
        );
        let established = ConnectionEstablishedFact {
            connection_id: built.fact.id,
            from_endpoint: built.response.from_endpoint,
            to_endpoint: built.response.to_endpoint,
            request_id: built.response.request_id,
            initiator_ephemeral_secret_fact_id: built.response.initiator_ephemeral_secret_fact_id,
            responder_ephemeral_secret_fact_id: built.response.responder_ephemeral_secret_fact_id,
            responder_ephemeral_public_key: built.response.responder_ephemeral_public_key,
            handshake_hash: built.response.handshake_hash,
            connection_secret: built.response.connection_secret,
            established_at_ms: received.received_at_local_ms,
        };
        let established_fact = Fact::new(
            FactScope::Local,
            received.received_at_local_ms,
            established_layout::encode_fact(&established)?,
        );

        Ok(PipelineEffects::new()
            .fact(responder_ephemeral_fact)
            .fact(response_sent_fact)
            .fact(established_fact))
    }
}

fn validate_fact_receipt(
    request_id: [u8; 32],
    request: &crate::protocol::connection::bootstrap_request::fact::BootstrapRequestFact,
    received: &crate::protocol::connection::fact_receipt::fact::ConnectionFactReceipt,
) -> Result<(), String> {
    if received.received_fact_id != request_id {
        return Err("create_bootstrap_response receive context targets another fact".into());
    }
    if received.receive_path
        != crate::protocol::connection::fact_receipt::fact::RECEIVE_PATH_CONNECTION_REQUEST
    {
        return Err("create_bootstrap_response requires connection request receipt".into());
    }
    if received.local_endpoint_id != request.to_endpoint {
        return Err("create_bootstrap_response request endpoint does not match receive".into());
    }
    if received.sender_endpoint_id != request.from_endpoint {
        return Err("create_bootstrap_response sender does not match receive".into());
    }
    if received.request_id != Some(request_id) {
        return Err("create_bootstrap_response fact receipt names another request".into());
    }
    Ok(())
}
