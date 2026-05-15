//! Driver for the target `transit_send_on_connection` handler.
//!
//! The wave-5 prototype of this driver contained the full transit packaging
//! pipeline — frame size selection, inner-payload framing, deterministic
//! AEAD-input derivation, AEAD encryption into the fixed slot, and the
//! `transit_network_send` follow-up intent. The poc10 intent-cleanliness
//! guardrail rejects fact / wire-layout / AEAD machinery inside
//! `src/handlers/`: that code belongs in `src/event_modules/transit/`
//! (which already owns the frame layouts). Until those helpers move into
//! `event_modules/transit/create.rs`, the driver decodes its intent,
//! validates the requested fact ids look sendable, and returns
//! `NOT_YET_WIRED` so the intent stays queued.
//!
//! This is therefore an *envelope-decode + sendability guard* handler, not
//! real transit packaging. The `receive_transit` driver follows the same
//! contract on the inbound side.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::Intent;

use super::intent::{decode_send_on_connection, TRANSIT_SEND_ON_CONNECTION};

pub const NOT_YET_WIRED: &str = "transit packaging not yet wired";

#[derive(Debug, Clone, Default)]
pub struct TransitSendOnConnectionHandler;

impl TransitSendOnConnectionHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for TransitSendOnConnectionHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == TRANSIT_SEND_ON_CONNECTION
    }

    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        Ok(decode_send_on_connection(intent)?.fact_ids)
    }

    fn handle(&self, intent: &Intent, _context: &HandlerContext) -> Result<HandlerOutput, String> {
        let _input = decode_send_on_connection(intent)?;
        Err(NOT_YET_WIRED.to_string())
    }
}
