//! Content-message projection rows.
//!
//! Rows are keyed by `workspace_id || message_id` so content-message
//! projections can scan all materialized messages in one workspace with a
//! bounded prefix scan. `content_messages` is authenticated message metadata;
//! `opened_message_rows` is plaintext materialized only after local decryption.

use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};
use crate::core::wire;

use super::fact::{
    AuthorId, ContentMessageFact, FrontierId, SignerId, WorkspaceId, UNIX_MINUTE_MS,
};

pub const CONTENT_MESSAGE_ROWS: TableName = TableName::new("content_messages");
pub const OPENED_MESSAGE_ROWS: TableName = TableName::new("opened_message_rows");
pub const MESSAGE_TOMBSTONE_ROWS: TableName = TableName::new("message_tombstone_rows");

pub const ROW_VALUE_BYTES: usize = 32 + 8 + 32 + 32 + 8 + 32 + 1;
pub const OPENED_MESSAGE_VALUE_PREFIX_BYTES: usize = 8 + 32 + 32 + 4;
pub const MESSAGE_TOMBSTONE_VALUE_BYTES: usize = 32 + 8;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentMessageRow {
    pub workspace_id: WorkspaceId,
    pub message_id: FactId,
    pub created_at_ms: u64,
    pub author_user_id: AuthorId,
    pub signer_id: FactId,
    pub frontier_id: FrontierId,
    pub minute: u64,
    pub leaf_id: FactId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedMessageRow {
    pub workspace_id: WorkspaceId,
    pub message_id: FactId,
    pub created_at_ms: u64,
    pub author_user_id: AuthorId,
    pub signer_id: SignerId,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageTombstoneRow {
    pub workspace_id: WorkspaceId,
    pub message_id: FactId,
    pub author_user_id: AuthorId,
    pub authored_minute: u64,
}

pub fn content_message_key(workspace_id: WorkspaceId, message_id: FactId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&message_id);
    key
}

pub fn content_message_row(message_id: FactId, fact: &ContentMessageFact) -> TableRow {
    let mut writer = wire::Writer::with_capacity(ROW_VALUE_BYTES);
    writer.fixed(&fact.author_user_id);
    writer.u64be(fact.created_at_ms);
    writer.fixed(&fact.signer_id);
    writer.fixed(&fact.frontier_id);
    writer.u64be(fact.minute);
    writer.fixed(&fact.leaf_id);
    writer.u8(0);
    TableRow {
        table: CONTENT_MESSAGE_ROWS,
        key: content_message_key(fact.workspace_id, message_id),
        value: writer.finish(),
    }
}

pub fn decode_content_message_row(key: &[u8], value: &[u8]) -> Result<ContentMessageRow, String> {
    if key.len() != 64 {
        return Err("content message row key is malformed".to_string());
    }
    if value.len() != ROW_VALUE_BYTES {
        return Err("content message row value is malformed".to_string());
    }
    let mut key_reader = wire::Reader::new(key);
    let workspace_id = key_reader.array().map_err(wire_err)?;
    let message_id = key_reader.array().map_err(wire_err)?;
    key_reader.finish().map_err(wire_err)?;
    let mut value_reader = wire::Reader::new(value);
    let row = ContentMessageRow {
        workspace_id,
        message_id,
        author_user_id: value_reader.array().map_err(wire_err)?,
        created_at_ms: value_reader.u64be().map_err(wire_err)?,
        signer_id: value_reader.array().map_err(wire_err)?,
        frontier_id: value_reader.array().map_err(wire_err)?,
        minute: value_reader.u64be().map_err(wire_err)?,
        leaf_id: value_reader.array().map_err(wire_err)?,
    };
    let deleted = value_reader.u8().map_err(wire_err)?;
    if deleted != 0 {
        return Err("content message row deleted flag is malformed".to_string());
    }
    value_reader.finish().map_err(wire_err)?;
    Ok(row)
}

pub fn opened_message_row(input: OpenedMessageRow) -> TableRow {
    let text = input.text.as_bytes();
    let mut writer = wire::Writer::with_capacity(OPENED_MESSAGE_VALUE_PREFIX_BYTES + text.len());
    writer.u64be(input.created_at_ms);
    writer.fixed(&input.author_user_id);
    writer.fixed(&input.signer_id);
    writer.u32be(text.len() as u32);
    writer.bytes(text);
    TableRow {
        table: OPENED_MESSAGE_ROWS,
        key: content_message_key(input.workspace_id, input.message_id),
        value: writer.finish(),
    }
}

pub fn decode_opened_message_row(key: &[u8], value: &[u8]) -> Result<OpenedMessageRow, String> {
    let (workspace_id, message_id) = decode_message_key(key, "opened message row key")?;
    let mut reader = wire::Reader::new(value);
    let created_at_ms = reader.u64be().map_err(wire_err)?;
    let author_user_id = reader.array().map_err(wire_err)?;
    let signer_id = reader.array().map_err(wire_err)?;
    let text_len = reader.u32be().map_err(wire_err)? as usize;
    let text = String::from_utf8(reader.bytes(text_len).map_err(wire_err)?.to_vec())
        .map_err(|err| format!("opened message text is not utf8: {err}"))?;
    reader.finish().map_err(wire_err)?;
    Ok(OpenedMessageRow {
        workspace_id,
        message_id,
        created_at_ms,
        author_user_id,
        signer_id,
        text,
    })
}

pub fn message_tombstone_row(
    workspace_id: WorkspaceId,
    message_id: FactId,
    author_user_id: AuthorId,
    created_at_ms: u64,
) -> TableRow {
    let mut writer = wire::Writer::with_capacity(MESSAGE_TOMBSTONE_VALUE_BYTES);
    writer.fixed(&author_user_id);
    writer.u64be(created_at_ms / UNIX_MINUTE_MS);
    TableRow {
        table: MESSAGE_TOMBSTONE_ROWS,
        key: content_message_key(workspace_id, message_id),
        value: writer.finish(),
    }
}

pub fn decode_message_tombstone_row(
    key: &[u8],
    value: &[u8],
) -> Result<MessageTombstoneRow, String> {
    let (workspace_id, message_id) = decode_message_key(key, "message tombstone key")?;
    let mut reader = wire::Reader::new(value);
    let row = MessageTombstoneRow {
        workspace_id,
        message_id,
        author_user_id: reader.array().map_err(wire_err)?,
        authored_minute: reader.u64be().map_err(wire_err)?,
    };
    reader.finish().map_err(wire_err)?;
    Ok(row)
}

fn decode_message_key(key: &[u8], label: &str) -> Result<(WorkspaceId, FactId), String> {
    if key.len() != 64 {
        return Err(format!("{label} must be workspace id plus message id"));
    }
    let mut reader = wire::Reader::new(key);
    let workspace_id = reader.array().map_err(wire_err)?;
    let message_id = reader.array().map_err(wire_err)?;
    reader.finish().map_err(wire_err)?;
    Ok((workspace_id, message_id))
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_message_row_round_trips_workspace_keyed_value() {
        let fact = ContentMessageFact {
            workspace_id: [1; 32],
            created_at_ms: 60_000,
            author_user_id: [2; 32],
            signer_id: [3; 32],
            frontier_id: [4; 32],
            local_history_node_secret_id: [5; 32],
            expires_at_minute: u64::MAX,
            disappearing_setting_id: [6; 32],
            minute: 1,
            leaf_id: [7; 32],
            nonce: [8; crate::protocol::facts::content::message::fact::NONCE_BYTES],
            ciphertext: b"sealed".to_vec(),
        };
        let row = content_message_row([9; 32], &fact);
        assert_eq!(row.key, content_message_key([1; 32], [9; 32]));
        let decoded = decode_content_message_row(&row.key, &row.value).expect("decode");
        assert_eq!(decoded.workspace_id, [1; 32]);
        assert_eq!(decoded.message_id, [9; 32]);
        assert_eq!(decoded.created_at_ms, 60_000);
        assert_eq!(decoded.author_user_id, [2; 32]);
        assert_eq!(decoded.signer_id, [3; 32]);
        assert_eq!(decoded.frontier_id, [4; 32]);
        assert_eq!(decoded.minute, 1);
        assert_eq!(decoded.leaf_id, [7; 32]);
    }

    #[test]
    fn opened_message_and_tombstone_rows_round_trip() {
        let opened = opened_message_row(OpenedMessageRow {
            workspace_id: [1; 32],
            message_id: [2; 32],
            created_at_ms: 60_000,
            author_user_id: [3; 32],
            signer_id: [4; 32],
            text: "hello".to_string(),
        });
        let decoded_opened =
            decode_opened_message_row(&opened.key, &opened.value).expect("decode opened");
        assert_eq!(decoded_opened.text, "hello");
        assert_eq!(decoded_opened.message_id, [2; 32]);

        let tombstone = message_tombstone_row([1; 32], [2; 32], [3; 32], 120_000);
        let decoded_tombstone = decode_message_tombstone_row(&tombstone.key, &tombstone.value)
            .expect("decode tombstone");
        assert_eq!(decoded_tombstone.authored_minute, 2);
        assert_eq!(decoded_tombstone.author_user_id, [3; 32]);
    }
}
