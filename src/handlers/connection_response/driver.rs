//! Driver for the target connection_response handler.
//!
//! Reads the inbound `connection_request` fact plus locally-supplied invite
//! and endpoint dependencies from the handler context, runs the native
//! responder key schedule (DH(eph_r, eph_i), DH(static_r, eph_i), invite
//! bootstrap secret, transcript-bound HKDF), and emits the canonical
//! `connection_response` fact. The fact is admitted through the usual
//! pipeline; transit framing belongs to the transit handler lane.

use crate::core::crypto::{self, X25519PublicKey};
use crate::core::facts::{Fact, FactScope};
use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::Intent;
use crate::event_modules::connection_request::layout as request_layout;
use crate::event_modules::connection_response::fact::ConnectionResponseFact;
use crate::event_modules::connection_response::layout as response_layout;
use crate::event_modules::identity_endpoint::layout as endpoint_layout;
use crate::event_modules::identity_invite::layout as invite_layout;

use super::intent::decode_connection_response_intent;

const HANDSHAKE_PURPOSE: &[u8] = b"topo-connection-handshake-v1";
const CONNECTION_SECRET_PURPOSE: &[u8] = b"topo-connection-secret-v1";
const TRANSCRIPT_LABEL: &[u8] = b"topo-native-connection-handshake-v1";

#[derive(Debug, Clone, Default)]
pub struct ConnectionResponseHandler;

impl ConnectionResponseHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for ConnectionResponseHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == super::intent::CONNECTION_RESPONSE
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
        if request.to_endpoint != endpoint.endpoint {
            return Err("connection_response endpoint does not match request".to_string());
        }
        if request.from_endpoint == endpoint.endpoint {
            return Err("connection_response endpoints must differ".to_string());
        }

        // The legacy formula also requires the responder ephemeral secret
        // event, which has no target fact form yet; we accept the inline
        // private key as a not-yet-wired-fact placeholder. If callers signal
        // a sentinel zero responder_ephemeral_secret_event_id together with a
        // zero ephemeral private key we cannot proceed.
        if input.responder_ephemeral_private_key == [0u8; 32]
            && input.responder_ephemeral_secret_event_id == [0u8; 32]
        {
            return Err("connection_response_dependency_not_wired".to_string());
        }

        let responder_ephemeral_public_key: X25519PublicKey =
            crypto::x25519_public_key(&input.responder_ephemeral_private_key);

        let ee = crypto::x25519_diffie_hellman(
            &input.responder_ephemeral_private_key,
            &request.initiator_ephemeral_public_key,
        );
        let es = crypto::x25519_diffie_hellman(
            &endpoint.secret,
            &request.initiator_ephemeral_public_key,
        );

        let transcript = public_transcript(
            input.request_id,
            &request,
            &responder_ephemeral_public_key,
        );

        let mut ikm = Vec::with_capacity(32 * 4);
        ikm.extend_from_slice(&invite.bootstrap_secret);
        ikm.extend_from_slice(&ee);
        ikm.extend_from_slice(&es);
        ikm.extend_from_slice(&request.bootstrap_hash);
        let response_key = crypto::hkdf_sha256_key(&ikm, HANDSHAKE_PURPOSE, &transcript)?;
        let handshake_hash = crypto::hash(&transcript);
        let connection_secret = crypto::hkdf_sha256_key(
            &response_key,
            CONNECTION_SECRET_PURPOSE,
            &handshake_hash,
        )?;

        let response = ConnectionResponseFact {
            from_endpoint: endpoint.endpoint,
            to_endpoint: request.from_endpoint,
            request_id: input.request_id,
            invite_secret_event_id: request.invite_secret_event_id,
            initiator_ephemeral_secret_event_id: request.initiator_ephemeral_secret_event_id,
            responder_ephemeral_secret_event_id: input.responder_ephemeral_secret_event_id,
            responder_ephemeral_public_key,
            handshake_hash,
            connection_secret,
        };
        let bytes = response_layout::encode_fact(&response)?;
        let fact = Fact::new(FactScope::Local, request_fact.timestamp, bytes);
        Ok(HandlerOutput::new().fact(fact))
    }
}

fn public_transcript(
    request_id: [u8; 32],
    request: &crate::event_modules::connection_request::fact::ConnectionRequestFact,
    responder_ephemeral_public_key: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(TRANSCRIPT_LABEL.len() + 32 * 10 + 64);
    out.extend_from_slice(TRANSCRIPT_LABEL);
    out.extend_from_slice(&request_id);
    out.extend_from_slice(&request.from_endpoint);
    out.extend_from_slice(&request.to_endpoint);
    out.extend_from_slice(&request.nonce);
    out.extend_from_slice(&request.invite_event_id);
    out.extend_from_slice(&request.bootstrap_hash);
    out.extend_from_slice(&request.invite_signature);
    out.extend_from_slice(&request.invite_secret_event_id);
    out.extend_from_slice(&request.initiator_ephemeral_secret_event_id);
    out.extend_from_slice(&request.initiator_ephemeral_public_key);
    out.extend_from_slice(responder_ephemeral_public_key);
    out
}
