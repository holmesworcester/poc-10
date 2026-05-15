//! Handler for `open_message` deferred intents.

use crate::core::handler_dispatch::{HandlerContext, HandlerOutput, IntentHandler};
use crate::core::intents::AtomicIntent;
use crate::core::intents::Intent;
use crate::event_modules::sealed_message::intent;

use super::opened_content_rows::{opened_message_row, OpenedContentRow};

#[derive(Debug, Clone, Default)]
pub struct OpenMessageHandler;

impl OpenMessageHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for OpenMessageHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == intent::OPEN_MESSAGE
    }

    fn handle(&self, intent: &Intent, _context: &HandlerContext) -> Result<HandlerOutput, String> {
        let opened = intent::decode_open_message_intent(intent)?;
        Ok(HandlerOutput::new().intent(
            AtomicIntent::PutRow(opened_message_row(OpenedContentRow {
                message_id: opened.message_id,
                minute: opened.minute,
                leaf_id: opened.leaf_id,
            }))
            .into_intent(),
        ))
    }
}
