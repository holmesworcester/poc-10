//! Driver for the target `connection_response` handler.
//!
//! The handler decodes its intent, loads the three dependency facts (the
//! inbound connection request, the local invite secret it matches, and the
//! local endpoint that owns the responder static material), runs the
//! cross-checks that depend on those decoded shapes, and then delegates
//! the actual handshake key schedule plus response-fact construction to
//! `event_modules::connection_response::create`. The cleanliness guardrail
//! keeps fact construction and AEAD / HKDF helpers under
//! `src/event_modules/`; the handler stays a bounded effect that wires
//! intent dispatch to the constructor.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::Intent;
use crate::event_modules::connection_request::layout as request_layout;
use crate::event_modules::connection_response::create::{
    build_responder_response, BuildResponderResponse,
};
use crate::event_modules::identity_endpoint::layout as endpoint_layout;
use crate::event_modules::identity_invite::layout as invite_layout;

use super::intent::decode_connection_response_intent;

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
