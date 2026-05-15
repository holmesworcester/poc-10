//! Handler for `purge_event` deferred intents.

use crate::core::handler_dispatch::{HandlerContext, HandlerOutput, IntentHandler};
use crate::core::intents::{Intent, TableDelete};
use crate::event_modules::sealed_message::intent;

use super::opened_content_rows::OPENED_CONTENT_ROWS;

#[derive(Debug, Clone, Default)]
pub struct PurgeEventHandler;

impl PurgeEventHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for PurgeEventHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == intent::PURGE_EVENT
    }

    fn handle(&self, intent: &Intent, _context: &HandlerContext) -> Result<HandlerOutput, String> {
        let purged = intent::decode_purge_event_intent(intent)?;
        Ok(HandlerOutput::new().intent(
            TableDelete {
                table: OPENED_CONTENT_ROWS,
                key: purged.message_id.to_vec(),
            }
            .into_intent(),
        ))
    }
}
