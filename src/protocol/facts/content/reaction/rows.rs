//! Content-reaction projection rows.
//!
//! Rows are keyed by `workspace_id || reaction_id` so display queries can scan
//! all reactions in a workspace without secondary indices. The value carries
//! the sealed envelope (target message, author, created_at_ms, nonce,
//! ciphertext); plaintext emoji projection is deferred to a later slice that
//! resolves the per-message decryption secret.

use crate::core::facts::FactId;
use crate::core::store::{Store, TableName, TableRow};
use crate::core::wire;
use rusqlite::params;

use super::fact::{AuthorId, WorkspaceId, REACTION_CIPHERTEXT_BYTES, REACTION_NONCE_BYTES};

pub const REACTION_ROWS: TableName = TableName::new("content_reactions");

pub const ROW_PREFIX_BYTES: usize = 32 + 32 + 8 + REACTION_NONCE_BYTES + 4;

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
    let mut writer = wire::Writer::with_capacity(ROW_PREFIX_BYTES + input.ciphertext.len() + 1);
    writer.fixed(&input.target_message_id);
    writer.fixed(&input.author_user_id);
    writer.u64be(input.created_at_ms);
    writer.fixed(&input.nonce);
    writer.u32be(input.ciphertext.len() as u32);
    writer.bytes(&input.ciphertext);
    writer.u8(0);
    Ok(TableRow {
        table: REACTION_ROWS,
        key: reaction_key(input.workspace_id, input.reaction_id),
        value: writer.finish(),
    })
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
        assert_eq!(row.key, reaction_key([1; 32], [2; 32]));
        assert_eq!(&row.value[..32], &[3; 32]);
        assert_eq!(&row.value[32..64], &[4; 32]);
        assert_eq!(&row.value[72..96], &[5; REACTION_NONCE_BYTES]);
        assert!(row.value.ends_with(&[b'r', 0]));
    }
}
