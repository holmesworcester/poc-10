//! Content-reaction projection rows.
//!
//! Rows are keyed by `workspace_id || reaction_id` so display queries can scan
//! all reactions in a workspace without secondary indices. The value carries
//! the sealed envelope (target message, author, created_at_ms, nonce,
//! ciphertext); plaintext emoji projection is deferred to a later slice that
//! resolves the per-message decryption secret.

use crate::core::facts::FactId;
use crate::core::schema_dsl::{self, FieldValue};
use crate::core::store::{TableName, TableRow};

use super::fact::{AuthorId, WorkspaceId, REACTION_CIPHERTEXT_BYTES, REACTION_NONCE_BYTES};

pub const REACTION_ROWS: TableName = TableName::new("content_reactions");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactionRow {
    pub workspace_id: WorkspaceId,
    pub reaction_id: FactId,
    pub created_at_ms: u64,
    pub target_message_id: FactId,
    pub author_user_id: AuthorId,
    pub nonce: [u8; REACTION_NONCE_BYTES],
    pub ciphertext: Vec<u8>,
}

pub fn reaction_key(workspace_id: WorkspaceId, reaction_id: FactId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&reaction_id);
    key
}

pub fn reaction_row(input: ReactionRow) -> Result<TableRow, String> {
    if input.ciphertext.len() > REACTION_CIPHERTEXT_BYTES {
        return Err("reaction row ciphertext exceeds fixed slot".to_string());
    }
    schema_dsl::encode_table_row(
        REACTION_ROWS,
        schema_dsl::facts_table("content_reactions"),
        &[
            (
                "workspace_id",
                FieldValue::Bytes(input.workspace_id.to_vec()),
            ),
            ("reaction_id", FieldValue::Bytes(input.reaction_id.to_vec())),
            (
                "message_id",
                FieldValue::Bytes(input.target_message_id.to_vec()),
            ),
            (
                "author_user_id",
                FieldValue::Bytes(input.author_user_id.to_vec()),
            ),
            ("created_at_ms", FieldValue::U64(input.created_at_ms)),
            ("nonce", FieldValue::Bytes(input.nonce.to_vec())),
            ("ciphertext", FieldValue::Bytes(input.ciphertext)),
            ("deleted", FieldValue::Bool(false)),
        ],
    )
}

pub fn decode_reaction_row(key: &[u8], value: &[u8]) -> Result<ReactionRow, String> {
    let record =
        schema_dsl::decode_table_row(schema_dsl::facts_table("content_reactions"), key, value)?;
    let ciphertext = record.bytes_vec("ciphertext")?;
    if ciphertext.len() > REACTION_CIPHERTEXT_BYTES {
        return Err("reaction row ciphertext exceeds fixed slot".to_string());
    }
    if record.bool("deleted")? {
        return Err("reaction row is deleted".to_string());
    }
    Ok(ReactionRow {
        workspace_id: record.bytes_array("workspace_id")?,
        reaction_id: record.bytes_array("reaction_id")?,
        created_at_ms: record.u64("created_at_ms")?,
        target_message_id: record.bytes_array("message_id")?,
        author_user_id: record.bytes_array("author_user_id")?,
        nonce: record.bytes_array("nonce")?,
        ciphertext,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reaction_row_round_trips_workspace_keyed_value() {
        let input = ReactionRow {
            workspace_id: [1; 32],
            reaction_id: [2; 32],
            created_at_ms: 5_000,
            target_message_id: [3; 32],
            author_user_id: [4; 32],
            nonce: [5; REACTION_NONCE_BYTES],
            ciphertext: b"r".to_vec(),
        };
        let row = reaction_row(input.clone()).expect("row");
        assert_eq!(row.key, reaction_key([1; 32], [2; 32]));
        assert_eq!(
            decode_reaction_row(&row.key, &row.value).expect("decode"),
            input
        );
    }
}
