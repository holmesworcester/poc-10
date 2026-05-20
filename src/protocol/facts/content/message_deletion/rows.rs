//! Content-message-deletion projection rows.
//!
//! Rows are keyed by `workspace_id || target_message_id` so the per-message
//! purge cascade can be authorized against the message's own author without a
//! secondary index. The value carries the deletion fact id, created_at_ms, and
//! deletion author. Per-message purge orchestration (frontier coords, retire
//! walks) lives in a separate handler and is deferred.

use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};
use crate::core::wire;

use super::fact::{AuthorId, WorkspaceId};

pub const MESSAGE_DELETION_ROWS: TableName = TableName::new("message_deletion_rows");

pub const ROW_VALUE_BYTES: usize = 32 + 8 + 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDeletionRow {
    pub workspace_id: WorkspaceId,
    pub target_message_id: FactId,
    pub deletion_id: FactId,
    pub created_at_ms: u64,
    pub author_user_id: AuthorId,
}

pub fn message_deletion_key(workspace_id: WorkspaceId, target_message_id: FactId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&target_message_id);
    key
}

pub fn message_deletion_row(input: MessageDeletionRow) -> Result<TableRow, String> {
    let mut writer = wire::Writer::with_capacity(ROW_VALUE_BYTES);
    writer.fixed(&input.deletion_id);
    writer.u64be(input.created_at_ms);
    writer.fixed(&input.author_user_id);
    Ok(TableRow {
        table: MESSAGE_DELETION_ROWS,
        key: message_deletion_key(input.workspace_id, input.target_message_id),
        value: writer.finish(),
    })
}

pub fn decode_message_deletion_row(key: &[u8], value: &[u8]) -> Result<MessageDeletionRow, String> {
    if key.len() != 64 {
        return Err("message deletion row key is malformed".to_string());
    }
    let mut key_reader = wire::Reader::new(key);
    let workspace_id = key_reader.array().map_err(wire_err)?;
    let target_message_id = key_reader.array().map_err(wire_err)?;
    key_reader.finish().map_err(wire_err)?;
    let mut value_reader = wire::Reader::new(value);
    let deletion_id = value_reader.array().map_err(wire_err)?;
    let created_at_ms = value_reader.u64be().map_err(wire_err)?;
    let author_user_id = value_reader.array().map_err(wire_err)?;
    value_reader.finish().map_err(wire_err)?;
    Ok(MessageDeletionRow {
        workspace_id,
        target_message_id,
        deletion_id,
        created_at_ms,
        author_user_id,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
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
        let row = message_deletion_row(input.clone()).expect("row");
        assert_eq!(row.key, message_deletion_key([1; 32], [2; 32]));
        assert_eq!(
            decode_message_deletion_row(&row.key, &row.value).expect("decode"),
            input
        );
    }
}
