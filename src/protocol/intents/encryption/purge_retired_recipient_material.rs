//! Handler for retired local recipient key material.
//!
//! Projection emits this intent after local recipient material is matched with a
//! superseding recipient key. The handler revalidates that exact relationship
//! against the loaded local fact, then purges the local secret through
//! `PipelineEffects`. It should not scan for other retired keys.

use crate::core::effects::PipelineEffects;
use crate::core::intents::Intent;
use crate::core::intents::{HandlerContext, HandlerFactId, HandlerResult, IntentHandler};
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
        Ok(PipelineEffects::new().purge_fact(input.local_recipient_key_id))
    }
}
