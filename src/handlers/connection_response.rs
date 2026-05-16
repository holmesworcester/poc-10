//! Target connection_response handler.
//!
//! Drives the responder side of the connection handshake: given a validated
//! inbound connection_request fact and the local responder material, produce
//! the canonical `connection_response` fact using the legacy native key
//! schedule (DH(eph_r, eph_i), DH(static_r, eph_i), invite bootstrap secret,
//! transcript-bound HKDF). The fact is then admitted through the usual fact
//! pipeline; transit framing belongs to the transit handler lane and is not
//! produced here.

//! Intent codec for the target `connection_response` handler.
//!
//! Payload layout (fixed-width, length-prefix style with each id explicitly
//! tagged by position): five 32-byte fields concatenated in order:
//!
//! 1. `request_id` — fact id of the inbound `connection_request` fact.
//! 2. `invite_secret_id` — fact id of the local `invite_secret` fact whose
//!    `bootstrap_hash` matches the request.
//! 3. `local_endpoint_id` — fact id of the local `endpoint` fact (carries the
//!    responder static x25519 secret).
//! 4. `responder_ephemeral_secret_event_id` — id pinned into the response so
//!    downstream replays can locate the ephemeral. Wave-local responder
//!    ephemeral facts are not yet emitted; callers may pass the hash of the
//!    ephemeral public key as a stable stand-in until the ephemeral fact
//!    lane lands.
//! 5. `responder_ephemeral_private_key` — x25519 private key bytes for the
//!    responder ephemeral. Threaded inline because the target tree has no
//!    `connection_ephemeral_secret` fact yet.
//!
//! This module intentionally does not pull in the core wire vocabulary:
//! the layout is a simple concatenation of fixed-width 32-byte ids.

use crate::core::intents::{Intent, IntentExecution, IntentKind};

/// 32-byte fact id, named locally to avoid pulling fact module types into
/// the handler intent file.
pub type FactId = [u8; 32];

pub const CONNECTION_RESPONSE: &str = "connection_response";

const FIELD_BYTES: usize = 32;
const FIELD_COUNT: usize = 5;
const PAYLOAD_BYTES: usize = FIELD_BYTES * FIELD_COUNT;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionResponseIntent {
    pub request_id: FactId,
    pub invite_secret_id: FactId,
    pub local_endpoint_id: FactId,
    pub responder_ephemeral_secret_event_id: FactId,
    pub responder_ephemeral_private_key: [u8; 32],
}

pub fn connection_response_intent(input: ConnectionResponseIntent) -> Intent {
    let payload = encode_payload(&input);
    let key = idempotence_key(&input);
    Intent::new(
        IntentKind::new(CONNECTION_RESPONSE).expect("valid connection response intent kind"),
        IntentExecution::Deferred,
        key,
        payload,
    )
}

pub fn decode_connection_response_intent(
    intent: &Intent,
) -> Result<ConnectionResponseIntent, String> {
    if intent.kind.as_str() != CONNECTION_RESPONSE {
        return Err("expected connection_response intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("connection_response intent must be deferred".to_string());
    }
    if intent.payload.len() != PAYLOAD_BYTES {
        return Err("connection_response payload has wrong length".to_string());
    }
    let input = ConnectionResponseIntent {
        request_id: take_id(&intent.payload, 0),
        invite_secret_id: take_id(&intent.payload, 1),
        local_endpoint_id: take_id(&intent.payload, 2),
        responder_ephemeral_secret_event_id: take_id(&intent.payload, 3),
        responder_ephemeral_private_key: take_id(&intent.payload, 4),
    };
    if intent.key != idempotence_key(&input) {
        return Err("connection_response idempotence key does not match payload".to_string());
    }
    Ok(input)
}

fn encode_payload(input: &ConnectionResponseIntent) -> Vec<u8> {
    let mut out = vec![0u8; PAYLOAD_BYTES];
    out[0..32].copy_from_slice(&input.request_id);
    out[32..64].copy_from_slice(&input.invite_secret_id);
    out[64..96].copy_from_slice(&input.local_endpoint_id);
    out[96..128].copy_from_slice(&input.responder_ephemeral_secret_event_id);
    out[128..160].copy_from_slice(&input.responder_ephemeral_private_key);
    out
}

fn idempotence_key(input: &ConnectionResponseIntent) -> Vec<u8> {
    // Idempotence key binds the request + responder ephemeral commitment so
    // repeated submissions for the same request and ephemeral collapse, while
    // a different responder ephemeral produces a distinct intent.
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"topo:connection-response-intent:v1:");
    hasher.update(&input.request_id);
    hasher.update(&input.invite_secret_id);
    hasher.update(&input.local_endpoint_id);
    hasher.update(&input.responder_ephemeral_secret_event_id);
    hasher.update(&input.responder_ephemeral_private_key);
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

    fn sample() -> ConnectionResponseIntent {
        ConnectionResponseIntent {
            request_id: [1; 32],
            invite_secret_id: [2; 32],
            local_endpoint_id: [3; 32],
            responder_ephemeral_secret_event_id: [4; 32],
            responder_ephemeral_private_key: [5; 32],
        }
    }

    #[test]
    fn intent_roundtrips() {
        let intent = connection_response_intent(sample());
        let decoded = decode_connection_response_intent(&intent).expect("decode");
        assert_eq!(decoded, sample());
    }

    #[test]
    fn rejects_wrong_kind() {
        let mut intent = connection_response_intent(sample());
        intent.kind = IntentKind::new("not_connection_response").unwrap();
        assert!(decode_connection_response_intent(&intent).is_err());
    }

    #[test]
    fn rejects_tampered_payload() {
        let mut intent = connection_response_intent(sample());
        intent.payload[0] ^= 0xff;
        assert!(decode_connection_response_intent(&intent).is_err());
    }

    #[test]
    fn rejects_atomic_execution() {
        let mut intent = connection_response_intent(sample());
        intent.execution = IntentExecution::Atomic;
        assert!(decode_connection_response_intent(&intent).is_err());
    }
}

// Handler for the target `connection_response` handler.
//
// The handler decodes its intent, loads the three dependency facts (the
// inbound connection request, the local invite secret it matches, and the
// local endpoint that owns the responder static material), runs the
// cross-checks that depend on those decoded shapes, and then delegates
// the actual handshake key schedule plus response-fact construction to
// `event_modules::connection_response::create`. The cleanliness guardrail
// keeps fact construction and AEAD / HKDF helpers under
// `src/event_modules/`; the handler stays a bounded effect that wires
// intent dispatch to the constructor.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::event_modules::connection_request::layout as request_layout;
use crate::event_modules::connection_response::create::{
    build_responder_response, BuildResponderResponse,
};
use crate::event_modules::identity_endpoint::layout as endpoint_layout;
use crate::event_modules::identity_invite::layout as invite_layout;

/// Sentinel returned when the intent carries a zero responder ephemeral
/// (the stand-in caller signal for "I have no ephemeral fact yet"). Real
/// connection_ephemeral_secret facts have to flow through before the
/// handler can compute the response.
pub const DEPENDENCY_NOT_WIRED: &str = "connection_response_dependency_not_wired";

#[derive(Debug, Clone, Default)]
pub struct ConnectionResponseHandler;

impl ConnectionResponseHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for ConnectionResponseHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == CONNECTION_RESPONSE
    }

    fn input_fact_ids(&self, raw_intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_connection_response_intent(raw_intent)?;
        Ok(vec![
            input.request_id,
            input.invite_secret_id,
            input.local_endpoint_id,
        ])
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = decode_connection_response_intent(intent)?;
        let request_fact = context.require_fact(&input.request_id)?;
        let invite_fact = context.require_fact(&input.invite_secret_id)?;
        let endpoint_fact = context.require_fact(&input.local_endpoint_id)?;

        let request = request_layout::decode_fact(&request_fact.bytes)?;
        let invite = invite_layout::decode_fact(&invite_fact.bytes)?;
        let endpoint = endpoint_layout::decode_fact(&endpoint_fact.bytes)?;

        if invite.bootstrap_hash != request.bootstrap_hash {
            return Err("connection_response invite does not match request".to_string());
        }
        if endpoint.endpoint != request.to_endpoint {
            return Err("connection_response endpoint does not match request".to_string());
        }
        if input.responder_ephemeral_private_key == [0u8; 32]
            && input.responder_ephemeral_secret_event_id == [0u8; 32]
        {
            return Err(DEPENDENCY_NOT_WIRED.to_string());
        }

        let built = build_responder_response(BuildResponderResponse {
            request_id: input.request_id,
            request: &request,
            invite: &invite,
            endpoint: &endpoint,
            responder_ephemeral_private_key: input.responder_ephemeral_private_key,
            responder_ephemeral_secret_event_id: input.responder_ephemeral_secret_event_id,
            created_at_ms: request_fact.timestamp,
        })?;
        Ok(HandlerOutput::new().fact(built.fact))
    }
}
