// Handler for accepted key-wrap recovery.
//
// Acceptance is represented by the queued intent and its declared facts. The
// handler does not scan for private keys or decide whether a wrap should have
// been accepted; it only opens the specific wrap with the specific local
// recipient material chosen by projection, then emits the resulting local
// secret fact back into the common pipeline.

use crate::core::intents::Intent;
use crate::core::intents::{
    HandlerContext, HandlerFactId, HandlerOutput, HandlerResult, IntentHandler,
};
use crate::protocol::facts::encryption::{create, intent};

#[derive(Debug, Clone, Default)]
pub struct UnwrapKeyWrapHandler;

impl UnwrapKeyWrapHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for UnwrapKeyWrapHandler {
    fn input_fact_ids(&self, raw_intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = intent::decode_unwrap_key_wrap_intent(raw_intent)?;
        // Loading is intentionally exact. A local device may hold several
        // recipient keys, but the projector selected the one whose context
        // matched this wrap.
        Ok(vec![
            input.key_wrap_id,
            input.local_recipient_key_id,
            input.recipient_key_id,
            input.frontier_id,
        ])
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = intent::decode_unwrap_key_wrap_intent(intent)?;
        let key_wrap = context.require_fact(&input.key_wrap_id)?;
        let local_recipient_key = context.require_fact(&input.local_recipient_key_id)?;
        let recipient = context.require_fact(&input.recipient_key_id)?;
        let frontier = context.require_fact(&input.frontier_id)?;
        let secret = create::unwrap_key_wrap_fact(
            &input,
            key_wrap,
            local_recipient_key,
            recipient,
            frontier,
        )?;
        Ok(HandlerOutput::new().fact(secret))
    }
}
