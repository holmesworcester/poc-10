//! Read-only queries over content-reaction projections.
//!
//! Rows are keyed by `workspace_id || reaction_id` so display queries can scan
//! all reactions in a workspace without secondary indices. The value carries
//! the sealed envelope (target message, author, created_at_ms, nonce,
//! ciphertext); CLI display opens the emoji after resolving the target
//! message content key. Keep this file as the place to ask "what reactions
//! does the store expose?" rather than "should this reaction be admitted?"

use crate::core::facts::FactId;
use crate::core::store::Store;
use rusqlite::params;

use super::fact::{AuthorId, WorkspaceId, REACTION_NONCE_BYTES};

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
