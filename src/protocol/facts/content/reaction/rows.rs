//! Content-reaction projection rows.
//!
//! Rows are keyed by `workspace_id || reaction_id` so display queries can scan
//! all reactions in a workspace without secondary indices. The value carries
//! the sealed envelope (target message, author, created_at_ms, nonce,
//! ciphertext); plaintext emoji projection is deferred to a later slice that
//! resolves the per-message decryption secret.

use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};
use crate::core::wire;

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
    let mut writer = wire::Writer::with_capacity(ROW_VALUE_BYTES);
    writer.u8(1);
    writer.u64be(input.created_at_ms);
    writer.fixed(&input.target_message_id);
    writer.fixed(&input.author_user_id);
    writer.fixed(&input.nonce);
    writer
        .fixed_slot::<REACTION_CIPHERTEXT_BYTES>(&input.ciphertext)
        .map_err(wire_err)?;
    Ok(TableRow {
        table: REACTION_ROWS,
        key: reaction_key(input.workspace_id, input.reaction_id),
        value: writer.finish(),
    })
}

pub fn decode_reaction_row(key: &[u8], value: &[u8]) -> Result<ReactionRow, String> {
    if key.len() != 64 {
        return Err("reaction row key is malformed".to_string());
    }
    if value.len() != ROW_VALUE_BYTES || value[0] != 1 {
        return Err("reaction row value is malformed".to_string());
    }
    let mut key_reader = wire::Reader::new(key);
    let workspace_id = key_reader.array().map_err(wire_err)?;
    let reaction_id = key_reader.array().map_err(wire_err)?;
    key_reader.finish().map_err(wire_err)?;
    let mut value_reader = wire::Reader::new(value);
    let version = value_reader.u8().map_err(wire_err)?;
    if version != 1 {
        return Err("reaction row value is malformed".to_string());
    }
    let row = ReactionRow {
        workspace_id,
        reaction_id,
        created_at_ms: value_reader.u64be().map_err(wire_err)?,
        target_message_id: value_reader.array().map_err(wire_err)?,
        author_user_id: value_reader.array().map_err(wire_err)?,
        nonce: value_reader.array().map_err(wire_err)?,
        ciphertext: value_reader
            .fixed_slot::<REACTION_CIPHERTEXT_BYTES>()
            .map_err(wire_err)?,
    };
    value_reader.finish().map_err(wire_err)?;
    Ok(row)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
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
