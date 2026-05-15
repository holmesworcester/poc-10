//! Transit send preparation guard.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::Intent;
use crate::event_modules::{encryption, signed_fact};

use super::intent::{
    decode_send_on_connection, TransitSendOnConnection, TRANSIT_SEND_ON_CONNECTION,
};

#[derive(Debug, Clone, Default)]
pub struct TransitSendOnConnectionHandler;

impl TransitSendOnConnectionHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for TransitSendOnConnectionHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == TRANSIT_SEND_ON_CONNECTION
    }

    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        Ok(decode_send_on_connection(intent)?.fact_ids)
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = decode_send_on_connection(intent)?;
        let _ = sendable_fact_bytes(&input, context)?;
        Err("send_on_connection has no live transit packaging handler yet".to_string())
    }
}

pub fn sendable_fact_bytes(
    input: &TransitSendOnConnection,
    context: &HandlerContext,
) -> Result<Vec<Vec<u8>>, String> {
    input
        .fact_ids
        .iter()
        .map(|fact_id| {
            let bytes = context.require_non_local_fact_bytes(fact_id)?;
            require_sendable_fact_bytes(fact_id, bytes)?;
            Ok(bytes.to_vec())
        })
        .collect()
}

pub fn require_sendable_fact_bytes(fact_id: &[u8; 32], bytes: &[u8]) -> Result<(), String> {
    if let Some(tag) = bytes.first().copied() {
        if is_known_private_or_local_fact_tag(tag) {
            return Err(format!(
                "transit send refused private/local fact tag {tag} for {:?}",
                fact_id
            ));
        }
    }
    Ok(())
}

fn is_known_private_or_local_fact_tag(tag: u8) -> bool {
    matches!(
        tag,
        signed_fact::layout::TYPE_LOCAL_SIGNER_SECRET
            | encryption::layout::TYPE_LOCAL_KEY_SECRET
            | encryption::layout::TYPE_LOCAL_HISTORY_NODE_SECRET
            | encryption::layout::TYPE_LOCAL_RECIPIENT_KEY
    )
}
