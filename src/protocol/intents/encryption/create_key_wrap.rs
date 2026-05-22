//! Handler for deterministic target key-wrap creation.
//!
//! The projector decides that a recipient, source secret, and signer capability
//! are allowed to meet; this handler only loads those declared facts and asks
//! the encryption module to build the signed wrap. Keeping the authorization
//! decision upstream prevents this handler from becoming a second, divergent
//! policy engine.

use crate::core::effects::PipelineEffects;
use crate::core::intents::Intent;
use crate::core::intents::{HandlerContext, HandlerFactId, HandlerResult, IntentHandler};
use crate::protocol::facts::encryption::{create, intent};

#[derive(Debug, Clone, Default)]
pub struct CreateKeyWrapHandler;

impl CreateKeyWrapHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for CreateKeyWrapHandler {
    fn input_fact_ids(&self, raw_intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = intent::decode_create_key_wrap_intent(raw_intent)?;
        // These inputs are the whole authority surface for key-wrap creation.
        // Any future dependency must be declared here before `handle` loads it.
        Ok(vec![
            input.recipient_key_id,
            input.source_fact_id,
            input.signer_secret_fact_id,
        ])
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = intent::decode_create_key_wrap_intent(intent)?;
        let recipient = context.require_fact(&input.recipient_key_id)?;
        let source = context.require_fact(&input.source_fact_id)?;
        let signer_secret = context.require_fact(&input.signer_secret_fact_id)?;
        let wrap = create::create_signed_key_wrap_fact(&input, recipient, source, signer_secret)?;
        Ok(PipelineEffects::new().fact(wrap))
    }
}
