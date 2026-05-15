//! Driver for outbound network frame send.
//!
//! Validates the outbound frame envelope (non-empty and within the max frame
//! budget) and then stops with `TCP_SEND_NOT_WIRED`, so the intent stays
//! queued for retry. The cursor fact that an earlier draft of this handler
//! emitted has been removed: the intent-cleanliness guardrail rejects fact
//! construction inside `src/handlers/`, and the cursor fact wire shape
//! belongs to an event-module port that has not landed yet. Duplicate
//! collapse is therefore enforced only at the deferred-intent layer (the
//! intent idempotence key dedupes identical `(routing_key, frame)` inputs);
//! a separate cursor module is a follow-up.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::Intent;

use super::intent::{
    decode_network_send_frame, NetworkSendFrame, MAX_FRAME_BYTES, NETWORK_SEND_FRAME,
};

/// Stable stop returned after envelope work succeeds, because the socket
/// write step is not yet wired. The intent stays queued so a future
/// transport hookup can retry the same intent without losing the frame.
pub const TCP_SEND_NOT_WIRED: &str = "tcp_send_not_yet_wired";

#[derive(Debug, Clone, Default)]
pub struct NetworkSendHandler;

impl NetworkSendHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for NetworkSendHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == NETWORK_SEND_FRAME
    }

    fn input_fact_ids(&self, _intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        Ok(Vec::new())
    }

    fn handle(&self, intent: &Intent, _context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = decode_network_send_frame(intent)?;
        validate_frame(&input)?;
        // Envelope passed. The actual TCP socket write is not yet wired and
        // the cursor fact construction was lifted to a future event module.
        // Return Err so the deferred-intent dispatcher keeps the intent
        // queued for retry once the transport lane is real.
        Err(TCP_SEND_NOT_WIRED.to_string())
    }
}

fn validate_frame(input: &NetworkSendFrame) -> Result<(), String> {
    if input.frame.is_empty() {
        return Err("network_send: frame bytes are empty".to_string());
    }
    if input.frame.len() > MAX_FRAME_BYTES {
        return Err(format!(
            "network_send: frame size {} exceeds max {MAX_FRAME_BYTES}",
            input.frame.len()
        ));
    }
    Ok(())
}
