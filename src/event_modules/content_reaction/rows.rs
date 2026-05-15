//! Content-reaction projection rows.
//!
//! Rows are keyed by `workspace_id || reaction_id` so display queries can scan
//! all reactions in a workspace without secondary indices. The value carries
//! the sealed envelope (target message, author, created_at_ms, nonce,
//! ciphertext); plaintext emoji projection is deferred to a later slice that
//! resolves the per-message decryption secret.

use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};
use crate::core::wire::{FixedLayout, FixedSlot};

use super::fact::{AuthorId, WorkspaceId, REACTION_CIPHERTEXT_BYTES, REACTION_NONCE_BYTES};

pub const REACTION_ROWS: TableName = TableName::new("reaction_rows");

pub const ROW_VALUE_BYTES: usize =
    1 + 8 + 32 + 32 + REACTION_NONCE_BYTES + 4 + REACTION_CIPHERTEXT_BYTES;

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
    let mut value = Vec::with_capacity(ROW_VALUE_BYTES);
    value.push(1);
    value.extend_from_slice(&input.created_at_ms.to_be_bytes());
    value.extend_from_slice(&input.target_message_id);
    value.extend_from_slice(&input.author_user_id);
    value.extend_from_slice(&input.nonce);
    let slot = FixedSlot::<REACTION_CIPHERTEXT_BYTES>::new(&input.ciphertext)
        .map_err(|err| format!("{err:?}"))?;
    let mut encoded = vec![0; 4 + REACTION_CIPHERTEXT_BYTES];
    slot.encode(&mut encoded).map_err(|err| format!("{err:?}"))?;
    value.extend_from_slice(&encoded);
    Ok(TableRow {
        table: REACTION_ROWS,
        key: reaction_key(input.workspace_id, input.reaction_id),
        value,
    })
}

pub fn decode_reaction_row(key: &[u8], value: &[u8]) -> Result<ReactionRow, String> {
    if key.len() != 64 {
        return Err("reaction row key is malformed".to_string());
    }
    if value.len() != ROW_VALUE_BYTES || value[0] != 1 {
        return Err("reaction row value is malformed".to_string());
    }
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&key[..32]);
    let mut reaction_id = [0; 32];
    reaction_id.copy_from_slice(&key[32..64]);
    let ciphertext_offset = 1 + 8 + 32 + 32 + REACTION_NONCE_BYTES;
    Ok(ReactionRow {
        workspace_id,
        reaction_id,
        created_at_ms: u64::from_be_bytes(value[1..9].try_into().unwrap()),
        target_message_id: value[9..41].try_into().unwrap(),
        author_user_id: value[41..73].try_into().unwrap(),
        nonce: value[73..97].try_into().unwrap(),
        ciphertext: FixedSlot::<REACTION_CIPHERTEXT_BYTES>::decode(&value[ciphertext_offset..])
            .map_err(|err| format!("{err:?}"))?
            .bytes()
            .to_vec(),
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
