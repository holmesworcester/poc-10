//! Handler manifest for event retention purge.

// Handler for retention purge of accepted facts.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::Intent;
use crate::protocol::facts::content::sealed_message::{intent, layout};

#[derive(Debug, Clone, Default)]
pub struct PurgeDeletedMessageHandler;

impl PurgeDeletedMessageHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for PurgeDeletedMessageHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == intent::PURGE_DELETED_MESSAGE
    }

    fn input_fact_ids(&self, raw_intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = intent::decode_purge_deleted_message_intent(raw_intent)?;
        Ok(vec![input.target_id, input.reason_fact_id])
    }

    fn handle(
        &self,
        raw_intent: &Intent,
        context: &HandlerContext,
    ) -> Result<HandlerOutput, String> {
        let input = intent::decode_purge_deleted_message_intent(raw_intent)?;
        if input.target_kind != intent::PURGE_TARGET_MESSAGE {
            return Err("purge_deleted_message target kind is not supported".to_string());
        }
        if input.reason_kind != intent::PURGE_REASON_AUTHOR_DELETION {
            return Err("purge_deleted_message reason kind is not supported".to_string());
        }

        let target = context.require_fact(&input.target_id)?;
        let reason = context.require_fact(&input.reason_fact_id)?;
        let message = layout::decode_sealed_message(&target.bytes)?;
        let deletion = layout::decode_message_deletion(&reason.bytes)?;
        if message.workspace_id != input.workspace_id {
            return Ok(HandlerOutput::new());
        }
        if deletion.workspace_id != input.workspace_id {
            return Ok(HandlerOutput::new());
        }
        if deletion.target_id != input.target_id {
            return Ok(HandlerOutput::new());
        }
        if deletion.author_user_id != message.author_user_id {
            return Ok(HandlerOutput::new());
        }

        Ok(HandlerOutput::new().purge_fact(input.target_id))
    }
}
