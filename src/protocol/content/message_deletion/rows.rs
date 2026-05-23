//! Content-message-deletion projection rows.
//!
//! Rows are keyed by `workspace_id || target_message_id` so the per-message
//! purge cascade can be authorized against the message's own author without a
//! secondary index. The value carries the deletion fact id, created_at_ms, and
//! deletion author. Per-message purge orchestration (frontier coords, retire
//! walks) lives in a separate handler and is deferred.

use crate::core::facts::FactId;
use crate::core::intents::TableInsert;
use crate::core::intents::Value;
use crate::core::store::TableName;
use crate::protocol::registry::read_models;

use super::fact::{AuthorId, WorkspaceId};

pub const MESSAGE_DELETION_ROWS: TableName = read_models::MESSAGE_DELETION_ROWS;
const MESSAGE_DELETION_COLUMNS: &[&str] = read_models::MESSAGE_DELETIONS.columns;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDeletionRow {
    pub workspace_id: WorkspaceId,
    pub target_message_id: FactId,
    pub deletion_id: FactId,
    pub created_at_ms: u64,
    pub author_user_id: AuthorId,
}

pub fn message_deletion_row(input: MessageDeletionRow) -> TableInsert {
    read_models::MESSAGE_DELETIONS.insert(vec![
        Value::Bytes(input.workspace_id.to_vec()),
        Value::Bytes(input.target_message_id.to_vec()),
        Value::Bytes(input.deletion_id.to_vec()),
        Value::U64(input.created_at_ms),
        Value::Bytes(input.author_user_id.to_vec()),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_deletion_row_round_trips() {
        let input = MessageDeletionRow {
            workspace_id: [1; 32],
            target_message_id: [2; 32],
            deletion_id: [3; 32],
            created_at_ms: 7_777,
            author_user_id: [4; 32],
        };
        let row = message_deletion_row(input);
        assert_eq!(row.table, MESSAGE_DELETION_ROWS);
        assert_eq!(row.columns, MESSAGE_DELETION_COLUMNS);
        assert_eq!(row.values[0], Value::Bytes(vec![1; 32]));
        assert_eq!(row.values[1], Value::Bytes(vec![2; 32]));
        assert_eq!(row.values[2], Value::Bytes(vec![3; 32]));
        assert_eq!(row.values[3], Value::U64(7_777));
        assert_eq!(row.values[4], Value::Bytes(vec![4; 32]));
    }
}
