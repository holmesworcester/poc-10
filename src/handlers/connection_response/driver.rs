//! Driver for the target `connection_response` handler.
//!
//! The wave-5 prototype of this driver ran the full responder key
//! schedule — DH(eph_r, eph_i), DH(static_r, eph_i), invite bootstrap
//! secret, transcript-bound HKDF — and emitted a `ConnectionResponseFact`
//! built from raw bytes. That code violates the poc10 intent-cleanliness
//! guardrail, which keeps fact construction and crypto helpers under
//! `src/event_modules/`. Until a `src/event_modules/connection_response/
//! create.rs` lifts the helpers across that boundary, the driver decodes
//! its intent, sanity-checks the dependency context, and stops with
//! `NOT_YET_WIRED` so the intent stays queued. The lifted fact builder
//! will eventually own the construction; this handler will then call into
//! it.
//!
//! This is therefore an *intent-decode + dependency-check* guard, not a
//! real handshake. It pairs with the `transit/driver.rs` stub on the
//! outbound side and with `receive_transit/driver.rs` on the inbound side.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::Intent;
use crate::event_modules::connection_request::layout as request_layout;
use crate::event_modules::identity_endpoint::layout as endpoint_layout;
use crate::event_modules::identity_invite::layout as invite_layout;

use super::intent::decode_connection_response_intent;

pub const NOT_YET_WIRED: &str = "connection_response key schedule not yet wired";

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

        Err(NOT_YET_WIRED.to_string())
    }
}
