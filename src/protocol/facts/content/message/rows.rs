//! Content-message projection rows.
//!
//! Rows are keyed by `workspace_id || message_id` so display queries can scan
//! all messages in one workspace with a bounded prefix scan. The value carries
//! author/timestamp/leaf metadata and a pointer to the sibling sealed-message
//! fact; plaintext text is not in this row (it lives in the sealed-message
//! projection once the per-message decryption secret resolves).

use crate::core::facts::FactId;
use crate::core::schema_dsl::{self, FieldValue};
use crate::core::store::{TableName, TableRow};

use super::fact::{AuthorId, ContentMessageFact, FrontierId, WorkspaceId};

pub const CONTENT_MESSAGE_ROWS: TableName = TableName::new("content_messages");

pub const ROW_VALUE_BYTES: usize = 32 + 8 + 32 + 8 + 32 + 32 + 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentMessageRow {
    pub workspace_id: WorkspaceId,
    pub message_id: FactId,
    pub author_user_id: AuthorId,
    pub created_at_ms: u64,
    pub frontier_id: FrontierId,
    pub minute: u64,
    pub leaf_id: FactId,
    pub sealed_body_ref: FactId,
}

pub fn content_message_key(workspace_id: WorkspaceId, message_id: FactId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&message_id);
    key
}

pub fn content_message_row(message_id: FactId, fact: &ContentMessageFact) -> TableRow {
    schema_dsl::encode_table_row(
        CONTENT_MESSAGE_ROWS,
        schema_dsl::facts_table("content_messages"),
        &[
            (
                "workspace_id",
                FieldValue::Bytes(fact.workspace_id.to_vec()),
            ),
            ("message_id", FieldValue::Bytes(message_id.to_vec())),
            (
                "author_user_id",
                FieldValue::Bytes(fact.author_user_id.to_vec()),
            ),
            ("created_at_ms", FieldValue::U64(fact.created_at_ms)),
            ("frontier_id", FieldValue::Bytes(fact.frontier_id.to_vec())),
            ("minute", FieldValue::U64(fact.minute)),
            ("leaf_id", FieldValue::Bytes(fact.leaf_id.to_vec())),
            (
                "sealed_message_id",
                FieldValue::Bytes(fact.sealed_body_ref.to_vec()),
            ),
            ("deleted", FieldValue::Bool(false)),
        ],
    )
    .expect("content_messages row matches schema")
}

pub fn decode_content_message_row(key: &[u8], value: &[u8]) -> Result<ContentMessageRow, String> {
    let record =
        schema_dsl::decode_table_row(schema_dsl::facts_table("content_messages"), key, value)?;
    if record.bool("deleted")? {
        return Err("content message row is deleted".to_string());
    }
    Ok(ContentMessageRow {
        workspace_id: record.bytes_array("workspace_id")?,
        message_id: record.bytes_array("message_id")?,
        author_user_id: record.bytes_array("author_user_id")?,
        created_at_ms: record.u64("created_at_ms")?,
        frontier_id: record.bytes_array("frontier_id")?,
        minute: record.u64("minute")?,
        leaf_id: record.bytes_array("leaf_id")?,
        sealed_body_ref: record.bytes_array("sealed_message_id")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_message_row_round_trips_workspace_keyed_value() {
        let fact = ContentMessageFact {
            workspace_id: [1; 32],
            author_user_id: [2; 32],
            created_at_ms: 60_000,
            frontier_id: [3; 32],
            minute: 1,
            leaf_id: [4; 32],
            sealed_body_ref: [5; 32],
        };
        let row = content_message_row([9; 32], &fact);
        assert_eq!(row.key, content_message_key([1; 32], [9; 32]));
        let decoded = decode_content_message_row(&row.key, &row.value).expect("decode");
        assert_eq!(decoded.workspace_id, [1; 32]);
        assert_eq!(decoded.message_id, [9; 32]);
        assert_eq!(decoded.author_user_id, [2; 32]);
        assert_eq!(decoded.created_at_ms, 60_000);
        assert_eq!(decoded.frontier_id, [3; 32]);
        assert_eq!(decoded.minute, 1);
        assert_eq!(decoded.leaf_id, [4; 32]);
        assert_eq!(decoded.sealed_body_ref, [5; 32]);
    }
}
