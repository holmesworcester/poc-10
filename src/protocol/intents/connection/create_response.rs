//! Target create_connection_response handler.
//!
//! Drives the responder side of the connection handshake: given a validated
//! inbound connection request fact, invite secret, receive provenance, and the
//! local endpoint capability, create fresh responder ephemeral material and
//! produce the canonical connection response fact using the legacy native key
//! schedule (DH(eph_r, eph_i), DH(static_r, eph_i), invite bootstrap secret,
//! transcript-bound HKDF). The response bytes are sent back over the bootstrap
//! return route; the emitted facts are admitted through the usual fact pipeline.

//! Intent codec for the target `create_connection_response` handler.
//!
//! Payload layout (fixed-width, with each id explicitly tagged by position):
//! three 32-byte fields concatenated in order:
//!
//! 1. `request_id` — fact id of the inbound connection request fact.
//! 2. `invite_secret_id` — fact id of the local `invite_secret` fact whose
//!    `bootstrap_hash` matches the request.
//! 3. `receive_id` — fact id of the `transport::transit_received`
//!    provenance fact proving the request was observed locally.
//!
//! This module intentionally does not pull in the core wire vocabulary:
//! the layout is a simple concatenation of fixed-width 32-byte ids.

use crate::core::intents::{Intent, IntentExecution, IntentKind};
use crate::core::schema_dsl::{self, FieldValue};

/// 32-byte fact id, named locally to avoid pulling fact module types into
/// the handler intent file.
pub type FactId = [u8; 32];

pub const CREATE_CONNECTION_RESPONSE: &str = "create_connection_response";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateConnectionResponse {
    pub request_id: FactId,
    pub invite_secret_id: FactId,
    pub receive_id: FactId,
}

pub fn create_connection_response_intent(input: CreateConnectionResponse) -> Intent {
    let payload = encode_payload(&input);
    let key = idempotence_key(&input);
    Intent::new(
        IntentKind::new(CREATE_CONNECTION_RESPONSE)
            .expect("valid create connection response intent kind"),
        IntentExecution::Deferred,
        key,
        payload,
    )
}

pub fn decode_create_connection_response_intent(
    intent: &Intent,
) -> Result<CreateConnectionResponse, String> {
    if intent.kind.as_str() != CREATE_CONNECTION_RESPONSE {
        return Err("expected create_connection_response intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("create_connection_response intent must be deferred".to_string());
    }
    let payload = schema_dsl::decode_layout_record(
        schema_dsl::intents_layout("create_connection_response_payload"),
        &intent.payload,
    )?;
    let input = CreateConnectionResponse {
        request_id: payload.bytes_array("request_id")?,
        invite_secret_id: payload.bytes_array("invite_secret_id")?,
        receive_id: payload.bytes_array("receive_id")?,
    };
    if intent.key != idempotence_key(&input) {
        return Err(
            "create_connection_response idempotence key does not match payload".to_string(),
        );
    }
    Ok(input)
}

fn encode_payload(input: &CreateConnectionResponse) -> Vec<u8> {
    schema_dsl::encode_layout_record(
        schema_dsl::intents_layout("create_connection_response_payload"),
        &[
            ("request_id", FieldValue::Bytes(input.request_id.to_vec())),
            (
                "invite_secret_id",
                FieldValue::Bytes(input.invite_secret_id.to_vec()),
            ),
            ("receive_id", FieldValue::Bytes(input.receive_id.to_vec())),
        ],
    )
    .expect("create_connection_response payload matches schema")
}

fn idempotence_key(input: &CreateConnectionResponse) -> Vec<u8> {
    // The request fact id is the bootstrap-response unit of work. Duplicate
    // deliveries may produce different provenance fact ids, but only one
    // response should be created for a request.
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo:create-connection-response-intent:v1:");
    hasher.update(&input.request_id);
    hasher.finalize().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CreateConnectionResponse {
        CreateConnectionResponse {
            request_id: [1; 32],
            invite_secret_id: [2; 32],
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
    fn rejects_wrong_kind() {
        let mut intent = create_connection_response_intent(sample());
        intent.kind = IntentKind::new("not_connection_response").unwrap();
        assert!(decode_create_connection_response_intent(&intent).is_err());
    }

    #[test]
    fn rejects_tampered_payload() {
        let mut intent = create_connection_response_intent(sample());
        intent.payload[0] ^= 0xff;
        assert!(decode_create_connection_response_intent(&intent).is_err());
    }

    #[test]
    fn rejects_atomic_execution() {
        let mut intent = create_connection_response_intent(sample());
        intent.execution = IntentExecution::Atomic;
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

// Handler for the target `create_connection_response` handler.
//
// The handler decodes its intent, loads the three dependency facts (the
// inbound connection request, the local invite secret it matches, and the
// receive-provenance fact), reloads the local endpoint capability from the
// store, and runs the cross-checks that depend on those decoded shapes. It then
// delegates the handshake key schedule plus response-fact construction to
// `facts::connection::response::create`. The cleanliness guardrail keeps fact
// construction and AEAD / HKDF helpers under `src/protocol/facts/`; the handler
// stays a bounded effect that wires intent dispatch to the constructor.

use crate::core::crypto;
use crate::core::facts::{Fact, FactScope};
use crate::core::handler_dispatch::{
    retry_intent, HandlerContext, HandlerFactId, HandlerOutput, IntentHandler,
};
use crate::core::network_queues::{NetworkTarget, OutboundNetworkRow};
use crate::core::tcp;
use crate::protocol::facts::connection::ephemeral_secret::{
    fact::ConnectionEphemeralSecretFact, layout as ephemeral_layout,
};
use crate::protocol::facts::connection::request::create as request_create;
use crate::protocol::facts::connection::request::layout as request_layout;
use crate::protocol::facts::connection::response::create::{
    build_responder_response, BuildResponderResponse,
};
use crate::protocol::facts::identity::endpoint::local_endpoint;
use crate::protocol::facts::identity::invite::layout as invite_layout;
use crate::protocol::facts::transport::transit_received;

#[derive(Debug, Clone, Default)]
pub struct CreateConnectionResponseHandler;

impl CreateConnectionResponseHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for CreateConnectionResponseHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == CREATE_CONNECTION_RESPONSE
    }

    fn input_fact_ids(&self, raw_intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_create_connection_response_intent(raw_intent)?;
        Ok(vec![
            input.request_id,
            input.invite_secret_id,
            input.receive_id,
        ])
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = decode_create_connection_response_intent(intent)?;
        let request_fact = context.require_fact(&input.request_id)?;
        let invite_fact = context.require_fact(&input.invite_secret_id)?;
        let receive_fact = context.require_fact(&input.receive_id)?;

        let request = request_layout::decode_fact(request_fact.body())?;
        let invite = invite_layout::decode_fact(&invite_fact.bytes)?;
        let received =
            transit_received::decode_fact_payload(receive_fact.body()).map_err(|_| {
                "create_connection_response receive context is not transport::transit provenance"
                    .to_string()
            })?;

        if request.invite_secret_fact_id != input.invite_secret_id {
            return Err(
                "create_connection_response invite context id does not match request".to_string(),
            );
        }
        if invite_fact.scope != FactScope::Local {
            return Err("create_connection_response invite context must be local".to_string());
        }
        if receive_fact.scope != FactScope::Local {
            return Err("create_connection_response receive context must be local".to_string());
        }
        request_create::validate_invite_signature(&request, &invite)?;
        validate_receive_provenance(input.request_id, &request, &received)?;
        let endpoint = local_endpoint::local_endpoint(context.store()?)?.ok_or_else(|| {
            "create_connection_response requires local endpoint state".to_string()
        })?;
        if endpoint.endpoint != request.to_endpoint
            || endpoint.endpoint != received.local_endpoint_id
        {
            return Err("create_connection_response endpoint does not match request".to_string());
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
        let return_addr = request
            .from_listen_addr
            .ok_or_else(|| "create_connection_response response route is missing".to_string())?;
        let target = NetworkTarget::new(return_addr);
        let row = OutboundNetworkRow::new(target, built.fact.bytes.clone());
        tcp::send_once(context.store()?, target, vec![row], (), |_, _| Ok(()))
            .map_err(|err| retry_intent(format!("create_connection_response tcp send: {err}")))?;

        Ok(HandlerOutput::new()
            .fact(responder_ephemeral_fact)
            .fact(built.fact))
    }
}

fn validate_receive_provenance(
    request_id: [u8; 32],
    request: &crate::protocol::facts::connection::request::fact::ConnectionRequestFact,
    received: &crate::protocol::facts::transport::transit_received::fact::TransitReceivedFact,
) -> Result<(), String> {
    if received.received_fact_id != request_id {
        return Err("create_connection_response receive context targets another fact".to_string());
    }
    if received.transit_kind
        != crate::protocol::facts::transport::transit_received::fact::TRANSIT_KIND_BOOTSTRAP
    {
        return Err("create_connection_response requires bootstrap receive provenance".to_string());
    }
    if received.local_endpoint_id != request.to_endpoint {
        return Err(
            "create_connection_response request endpoint does not match receive".to_string(),
        );
    }
    if received.sender_endpoint_id != request.from_endpoint {
        return Err("create_connection_response sender does not match receive".to_string());
    }
    if received.request_id != Some(request_id) {
        return Err(
            "create_connection_response receive provenance names another request".to_string(),
        );
    }
    Ok(())
}
