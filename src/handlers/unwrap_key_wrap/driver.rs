//! Driver for accepted key-wrap recovery.

use crate::core::handler_dispatch::{HandlerContext, HandlerOutput, IntentHandler};
use crate::core::intents::Intent;
use crate::event_modules::encryption::{create, intent};

#[derive(Debug, Clone, Default)]
pub struct UnwrapKeyWrapHandler;

impl UnwrapKeyWrapHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for UnwrapKeyWrapHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == intent::UNWRAP_KEY_WRAP
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = intent::decode_unwrap_key_wrap_intent(intent)?;
        let key_wrap = context.require_fact(&input.key_wrap_id)?;
        let local_recipient_key = context.require_fact(&input.local_recipient_key_id)?;
        let recipient = context.require_fact(&input.recipient_key_id)?;
        let secret =
            create::unwrap_key_wrap_fact(&input, key_wrap, local_recipient_key, recipient)?;
        Ok(HandlerOutput::new().fact(secret))
    }
}
