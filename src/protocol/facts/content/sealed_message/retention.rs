//! Helpers for bounded message retention purges.

use crate::core::facts::{Fact, FactId};
use crate::core::store::Store;
use crate::protocol::facts::{
    content::{message, sealed_message},
    identity::signed_fact,
};

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

impl RetentionMessageView for sealed_message::fact::SealedMessageFact {
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

pub fn decode_sealed_message_fact(
    fact: &Fact,
) -> Result<sealed_message::fact::SealedMessageFact, String> {
    match fact.bytes.first().copied() {
        Some(sealed_message::layout::TYPE_SEALED_MESSAGE) => {
            sealed_message::layout::decode_sealed_message(fact.body())
        }
        Some(signed_fact::layout::TYPE_SIGNED_FACT) => {
            let envelope = signed_fact::layout::decode_signed_fact(fact.body())?;
            if envelope.inner_type != sealed_message::layout::TYPE_SEALED_MESSAGE {
                return Err("signed fact does not contain a sealed message".to_string());
            }
            sealed_message::layout::decode_sealed_message(&envelope.payload)
        }
        _ => Err("expected sealed message fact".to_string()),
    }
}

pub fn decode_message_fact(fact: &Fact) -> Result<MessageRetentionFact, String> {
    match fact.bytes.first().copied() {
        Some(message::layout::TYPE_CONTENT_MESSAGE) => {
            content_message_retention(message::layout::decode_fact(fact.body())?)
        }
        Some(sealed_message::layout::TYPE_SEALED_MESSAGE) => {
            sealed_message_retention(sealed_message::layout::decode_sealed_message(fact.body())?)
        }
        Some(signed_fact::layout::TYPE_SIGNED_FACT) => {
            let envelope = signed_fact::layout::decode_signed_fact(fact.body())?;
            match envelope.inner_type {
                message::layout::TYPE_CONTENT_MESSAGE => {
                    content_message_retention(message::layout::decode_fact(&envelope.payload)?)
                }
                sealed_message::layout::TYPE_SEALED_MESSAGE => sealed_message_retention(
                    sealed_message::layout::decode_sealed_message(&envelope.payload)?,
                ),
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
    let key = sealed_message::rows::message_key(workspace_id, message_id);
    let tombstone = sealed_message::rows::message_tombstone_row(
        workspace_id,
        message_id,
        message.author_user_id(),
        message.created_at_ms(),
    );
    store
        .write_transaction(|tx| {
            tx.insert_table_rows_in_tx(vec![tombstone])?;
            tx.delete_table_rows_in_tx(sealed_message::rows::MESSAGE_ROWS, vec![key.clone()])?;
            tx.delete_table_rows_in_tx(
                sealed_message::rows::OPENED_MESSAGE_ROWS,
                vec![key.clone()],
            )?;
            tx.delete_table_rows_in_tx(
                message::rows::CONTENT_MESSAGE_ROWS,
                vec![message::rows::content_message_key(workspace_id, message_id)],
            )?;
            tx.delete_table_rows_in_tx(sealed_message::rows::SEALED_MESSAGE_ROWS, vec![key])?;
            Ok(())
        })
        .map_err(|err| format!("{context}: {err}"))?;
    Ok(())
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

fn sealed_message_retention(
    message: sealed_message::fact::SealedMessageFact,
) -> Result<MessageRetentionFact, String> {
    Ok(MessageRetentionFact {
        workspace_id: message.workspace_id,
        created_at_ms: message.created_at_ms,
        author_user_id: message.author_user_id,
        minute: message.minute,
        expires_at_minute: message.expires_at_minute,
    })
}
