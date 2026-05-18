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

pub fn decode_reaction_row(key: &[u8], value: &[u8]) -> Result<ReactionRow, String> {
    if key.len() != 64 {
        return Err("reaction row key is malformed".to_string());
    }
    if value.len() < ROW_PREFIX_BYTES + 1 {
        return Err("reaction row value is malformed".to_string());
    }
    let mut key_reader = wire::Reader::new(key);
    let workspace_id = key_reader.array().map_err(wire_err)?;
    let reaction_id = key_reader.array().map_err(wire_err)?;
    key_reader.finish().map_err(wire_err)?;
    let mut value_reader = wire::Reader::new(value);
    let target_message_id = value_reader.array().map_err(wire_err)?;
    let author_user_id = value_reader.array().map_err(wire_err)?;
    let created_at_ms = value_reader.u64be().map_err(wire_err)?;
    let nonce = value_reader.array().map_err(wire_err)?;
    let ciphertext_len = value_reader.u32be().map_err(wire_err)? as usize;
    if ciphertext_len > REACTION_CIPHERTEXT_BYTES {
        return Err("reaction row ciphertext exceeds fixed slot".to_string());
    }
    if value.len() != ROW_PREFIX_BYTES + ciphertext_len + 1 {
        return Err("reaction row value is malformed".to_string());
    }
    let ciphertext = value_reader
        .bytes(ciphertext_len)
        .map_err(wire_err)?
        .to_vec();
    let deleted = value_reader.u8().map_err(wire_err)?;
    if deleted > 1 {
        return Err("reaction row deleted flag is malformed".to_string());
    }
    let row = ReactionRow {
        workspace_id,
        reaction_id,
        created_at_ms,
        target_message_id,
        author_user_id,
        nonce,
        ciphertext,
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
