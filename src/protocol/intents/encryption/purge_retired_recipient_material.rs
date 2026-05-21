// Handler for retired local recipient key material.

use crate::core::intents::Intent;
use crate::core::intents::{
    HandlerContext, HandlerFactId, HandlerOutput, HandlerResult, IntentHandler,
};
use crate::protocol::facts::encryption::{create, intent};

#[derive(Debug, Clone, Default)]
pub struct PurgeRetiredRecipientMaterialHandler;

impl PurgeRetiredRecipientMaterialHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for PurgeRetiredRecipientMaterialHandler {
    fn input_fact_ids(&self, raw_intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = intent::decode_purge_retired_recipient_material_intent(raw_intent)?;
        Ok(vec![input.local_recipient_key_id])
    }

    fn handle(&self, raw_intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = intent::decode_purge_retired_recipient_material_intent(raw_intent)?;
        let local = context.require_fact(&input.local_recipient_key_id)?;
        create::validate_retired_recipient_material(&input, local)?;
        Ok(HandlerOutput::new().purge_fact(input.local_recipient_key_id))
    }
}
