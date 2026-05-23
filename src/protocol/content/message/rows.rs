//! Content-message projection rows.
//!
//! Rows are keyed by `workspace_id || message_id` so content-message
//! projections can scan all materialized messages in one workspace with a
//! bounded prefix scan. `content_messages` is authenticated message metadata;
//! `opened_message_rows` is plaintext materialized only after local decryption.

use crate::core::facts::FactId;
use crate::core::intents::TableInsert;
use crate::core::intents::Value;
use crate::core::store::TableName;
use crate::protocol::registry::read_models;

use super::fact::{
    AuthorId, ContentMessageFact, FrontierId, SignerId, WorkspaceId, UNIX_MINUTE_MS,
};

pub const CONTENT_MESSAGE_ROWS: TableName = read_models::CONTENT_MESSAGE_ROWS;
pub const OPENED_MESSAGE_ROWS: TableName = read_models::OPENED_MESSAGE_ROWS;
pub const MESSAGE_TOMBSTONE_ROWS: TableName = read_models::MESSAGE_TOMBSTONE_ROWS;

pub(crate) const MESSAGE_KEY_COLUMNS: &[&str] = read_models::CONTENT_MESSAGES.key_columns;
#[cfg(test)]
const CONTENT_MESSAGE_COLUMNS: &[&str] = read_models::CONTENT_MESSAGES.columns;
#[cfg(test)]
const OPENED_MESSAGE_COLUMNS: &[&str] = read_models::OPENED_MESSAGES.columns;
#[cfg(test)]
const MESSAGE_TOMBSTONE_COLUMNS: &[&str] = read_models::MESSAGE_TOMBSTONES.columns;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentMessageRow {
    pub workspace_id: WorkspaceId,
    pub message_id: FactId,
    pub created_at_ms: u64,
    pub author_user_id: AuthorId,
    pub signer_id: FactId,
    pub frontier_id: FrontierId,
    pub minute: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedMessageRow {
    pub workspace_id: WorkspaceId,
    pub message_id: FactId,
    pub created_at_ms: u64,
    pub author_user_id: AuthorId,
    pub signer_id: SignerId,
    pub text: String,
}

pub fn content_message_row(message_id: FactId, fact: &ContentMessageFact) -> TableInsert {
    read_models::CONTENT_MESSAGES.insert(vec![
        Value::Bytes(fact.workspace_id.to_vec()),
        Value::Bytes(message_id.to_vec()),
        Value::Bytes(fact.author_user_id.to_vec()),
        Value::U64(fact.created_at_ms),
        Value::Bytes(fact.signer_id.to_vec()),
        Value::Bytes(fact.frontier_id.to_vec()),
        Value::U64(fact.minute),
        Value::Bool(false),
    ])
}

pub fn opened_message_row(input: OpenedMessageRow) -> TableInsert {
    read_models::OPENED_MESSAGES.insert(vec![
        Value::Bytes(input.workspace_id.to_vec()),
        Value::Bytes(input.message_id.to_vec()),
        Value::U64(input.created_at_ms),
        Value::Bytes(input.author_user_id.to_vec()),
        Value::Bytes(input.signer_id.to_vec()),
        Value::Bytes(input.text.into_bytes()),
    ])
}

pub fn message_tombstone_row(
    workspace_id: WorkspaceId,
    message_id: FactId,
    author_user_id: AuthorId,
    created_at_ms: u64,
) -> TableInsert {
    message_tombstone_row_at_minute(
        workspace_id,
        message_id,
        author_user_id,
        created_at_ms / UNIX_MINUTE_MS,
    )
}

pub fn message_tombstone_row_at_minute(
    workspace_id: WorkspaceId,
    message_id: FactId,
    author_user_id: AuthorId,
    authored_minute: u64,
) -> TableInsert {
    read_models::MESSAGE_TOMBSTONES.insert(vec![
        Value::Bytes(workspace_id.to_vec()),
        Value::Bytes(message_id.to_vec()),
        Value::Bytes(author_user_id.to_vec()),
        Value::U64(authored_minute),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_message_row_round_trips_workspace_keyed_value() {
        let fact = ContentMessageFact {
            workspace_id: [1; 32],
            created_at_ms: 60_000,
            author_user_id: [2; 32],
            signer_id: [3; 32],
            frontier_id: [4; 32],
            local_history_node_secret_id: [5; 32],
            expires_at_minute: u64::MAX,
            disappearing_setting_id: [6; 32],
            minute: 1,
            nonce: [8; crate::protocol::content::message::fact::NONCE_BYTES],
            ciphertext: b"sealed".to_vec(),
        };
        let row = content_message_row([9; 32], &fact);
        assert_eq!(row.table, CONTENT_MESSAGE_ROWS);
        assert_eq!(row.columns, CONTENT_MESSAGE_COLUMNS);
        assert_eq!(row.values[0], Value::Bytes(vec![1; 32]));
        assert_eq!(row.values[1], Value::Bytes(vec![9; 32]));
        assert_eq!(row.values[2], Value::Bytes(vec![2; 32]));
        assert_eq!(row.values[4], Value::Bytes(vec![3; 32]));
        assert_eq!(row.values[5], Value::Bytes(vec![4; 32]));
        assert_eq!(row.values[7], Value::Bool(false));
    }

    #[test]
    fn opened_message_and_tombstone_rows_round_trip() {
        let opened = opened_message_row(OpenedMessageRow {
            workspace_id: [1; 32],
            message_id: [2; 32],
            created_at_ms: 60_000,
            author_user_id: [3; 32],
            signer_id: [4; 32],
            text: "hello".to_string(),
        });
        assert_eq!(opened.table, OPENED_MESSAGE_ROWS);
        assert_eq!(opened.columns, OPENED_MESSAGE_COLUMNS);
        assert_eq!(opened.values[5], Value::Bytes(b"hello".to_vec()));

        let tombstone = message_tombstone_row([1; 32], [2; 32], [3; 32], 120_000);
        assert_eq!(tombstone.table, MESSAGE_TOMBSTONE_ROWS);
        assert_eq!(tombstone.columns, MESSAGE_TOMBSTONE_COLUMNS);
        assert_eq!(tombstone.values[2], Value::Bytes(vec![3; 32]));
        assert_eq!(tombstone.values[3], Value::U64(2));
    }
}
