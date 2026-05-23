//! Content-reaction projection rows.
//!
//! Rows are keyed by `workspace_id || reaction_id` so display queries can scan
//! all reactions in a workspace without secondary indices. The value carries
//! the sealed envelope (target message, author, created_at_ms, nonce,
//! ciphertext); plaintext emoji projection is deferred to a later slice that
//! resolves the per-message decryption secret.

use crate::core::facts::FactId;
use crate::core::intents::TableInsert;
use crate::core::intents::Value;
use crate::core::store::{Store, TableName};
use crate::protocol::registry::read_models;
use rusqlite::params;

use super::fact::{AuthorId, WorkspaceId, REACTION_CIPHERTEXT_BYTES, REACTION_NONCE_BYTES};

pub const REACTION_ROWS: TableName = read_models::REACTION_ROWS;
pub(crate) const REACTION_KEY_COLUMNS: &[&str] = read_models::CONTENT_REACTIONS.key_columns;
const REACTION_COLUMNS: &[&str] = read_models::CONTENT_REACTIONS.columns;

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

pub fn reaction_row(input: ReactionRow) -> Result<TableInsert, String> {
    if input.ciphertext.len() > REACTION_CIPHERTEXT_BYTES {
        return Err("reaction row ciphertext exceeds fixed slot".to_string());
    }
    Ok(read_models::CONTENT_REACTIONS.insert(vec![
        Value::Bytes(input.workspace_id.to_vec()),
        Value::Bytes(input.reaction_id.to_vec()),
        Value::Bytes(input.target_message_id.to_vec()),
        Value::Bytes(input.author_user_id.to_vec()),
        Value::U64(input.created_at_ms),
        Value::Bytes(input.nonce.to_vec()),
        Value::Bytes(input.ciphertext),
        Value::Bool(false),
    ]))
}

pub fn reaction_rows_for_workspace(
    store: &Store,
    workspace_id: WorkspaceId,
) -> Result<Vec<ReactionRow>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT reaction_id, message_id, author_user_id, created_at_ms, nonce, ciphertext
             FROM content_reactions
             WHERE workspace_id = ?1 AND deleted = 0
             ORDER BY created_at_ms, reaction_id",
        )
        .map_err(|err| format!("load reaction rows: {err}"))?;
    let rows = stmt
        .query_map(params![workspace_id], |row| {
            Ok(ReactionRow {
                workspace_id,
                reaction_id: row.get(0)?,
                target_message_id: row.get(1)?,
                author_user_id: row.get(2)?,
                created_at_ms: row.get::<_, i64>(3)? as u64,
                nonce: row.get(4)?,
                ciphertext: row.get(5)?,
            })
        })
        .map_err(|err| format!("load reaction rows: {err}"))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("decode reaction rows: {err}"))?;
    Ok(rows)
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
        let row = reaction_row(input).expect("row");
        assert_eq!(row.table, REACTION_ROWS);
        assert_eq!(row.columns, REACTION_COLUMNS);
        assert_eq!(row.values[0], Value::Bytes(vec![1; 32]));
        assert_eq!(row.values[1], Value::Bytes(vec![2; 32]));
        assert_eq!(row.values[2], Value::Bytes(vec![3; 32]));
        assert_eq!(row.values[3], Value::Bytes(vec![4; 32]));
        assert_eq!(row.values[5], Value::Bytes(vec![5; REACTION_NONCE_BYTES]));
        assert_eq!(row.values[6], Value::Bytes(b"r".to_vec()));
        assert_eq!(row.values[7], Value::Bool(false));
    }
}
