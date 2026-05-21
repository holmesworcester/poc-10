//! Helpers for bounded message retention purges.

use crate::core::facts::{Fact, FactId};
use crate::core::intents::{RowMutation, TableDeleteWhere};
use crate::core::pipeline::{commit_pipeline_effects_to_store, PipelineEffects};
use crate::core::select::Value;
use crate::core::store::Store;
use crate::core::store::TableName;
use crate::protocol::facts::{content::message, identity::signed_fact};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRetentionFact {
    pub workspace_id: FactId,
    pub created_at_ms: u64,
    pub author_user_id: FactId,
    pub minute: u64,
    pub expires_at_minute: u64,
}

pub trait RetentionMessageView {
    fn workspace_id(&self) -> FactId;
    fn created_at_ms(&self) -> u64;
    fn author_user_id(&self) -> FactId;
    fn minute(&self) -> u64;
    fn expires_at_minute(&self) -> u64;
}

impl RetentionMessageView for MessageRetentionFact {
    fn workspace_id(&self) -> FactId {
        self.workspace_id
    }

    fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    fn author_user_id(&self) -> FactId {
        self.author_user_id
    }

    fn minute(&self) -> u64 {
        self.minute
    }

    fn expires_at_minute(&self) -> u64 {
        self.expires_at_minute
    }
}

pub fn decode_message_fact(fact: &Fact) -> Result<MessageRetentionFact, String> {
    match fact.bytes.first().copied() {
        Some(message::layout::TYPE_CONTENT_MESSAGE) => {
            content_message_retention(message::layout::decode_fact(fact.body())?)
        }
        Some(signed_fact::layout::TYPE_SIGNED_FACT) => {
            let envelope = signed_fact::layout::decode_signed_fact(fact.body())?;
            match envelope.inner_type {
                message::layout::TYPE_CONTENT_MESSAGE => {
                    content_message_retention(message::layout::decode_fact(&envelope.payload)?)
                }
                _ => Err("signed fact does not contain a message".to_string()),
            }
        }
        _ => Err("expected message fact".to_string()),
    }
}

pub fn delete_message_projection(
    store: &Store,
    message_id: FactId,
    message: &impl RetentionMessageView,
    context: &str,
) -> Result<(), String> {
    let workspace_id = message.workspace_id();
    let effects = PipelineEffects::new()
        .row_mutation(RowMutation::InsertValues(
            message::rows::message_tombstone_row(
                workspace_id,
                message_id,
                message.author_user_id(),
                message.created_at_ms(),
            ),
        ))
        .row_mutation(RowMutation::DeleteWhere(message_row_delete(
            message::rows::OPENED_MESSAGE_ROWS,
            workspace_id,
            message_id,
        )))
        .row_mutation(RowMutation::DeleteWhere(message_row_delete(
            message::rows::CONTENT_MESSAGE_ROWS,
            workspace_id,
            message_id,
        )));
    commit_pipeline_effects_to_store(
        store,
        &effects,
        &[
            message::rows::MESSAGE_TOMBSTONE_ROWS,
            message::rows::OPENED_MESSAGE_ROWS,
            message::rows::CONTENT_MESSAGE_ROWS,
        ],
        context,
    )?;
    Ok(())
}

pub(crate) fn message_row_delete(
    table: TableName,
    workspace_id: FactId,
    message_id: FactId,
) -> TableDeleteWhere {
    TableDeleteWhere {
        table,
        columns: message::rows::MESSAGE_KEY_COLUMNS,
        values: vec![
            Value::Bytes(workspace_id.to_vec()),
            Value::Bytes(message_id.to_vec()),
        ],
    }
}

fn content_message_retention(
    message: message::fact::ContentMessageFact,
) -> Result<MessageRetentionFact, String> {
    Ok(MessageRetentionFact {
        workspace_id: message.workspace_id,
        created_at_ms: message.created_at_ms,
        author_user_id: message.author_user_id,
        minute: message.minute,
        expires_at_minute: message.expires_at_minute,
    })
}
