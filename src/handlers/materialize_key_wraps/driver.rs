//! Driver for deterministic target key-wrap materialization.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::Intent;
use crate::event_modules::encryption::{create, intent};

#[derive(Debug, Clone, Default)]
pub struct MaterializeKeyWrapsHandler;

impl MaterializeKeyWrapsHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for MaterializeKeyWrapsHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == intent::MATERIALIZE_KEY_WRAPS
    }

    fn input_fact_ids(&self, raw_intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = intent::decode_materialize_key_wraps_intent(raw_intent)?;
        Ok(vec![
            input.recipient_key_id,
            input.source_fact_id,
            input.signer_secret_fact_id,
        ])
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = intent::decode_materialize_key_wraps_intent(intent)?;
        let recipient = context.require_fact(&input.recipient_key_id)?;
        let source = context.require_fact(&input.source_fact_id)?;
        let signer_secret = context.require_fact(&input.signer_secret_fact_id)?;
        let wrap =
            create::materialize_signed_key_wrap_fact(&input, recipient, source, signer_secret)?;
        Ok(HandlerOutput::new().fact(wrap))
    }
}
