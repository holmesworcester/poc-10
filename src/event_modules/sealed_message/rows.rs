//! Projection row layouts for sealed-message state.

use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};
use crate::core::wire::{FixedLayout, FixedSlot};

use super::fact::{
    AuthorId, FrontierId, SignerId, WorkspaceId, CIPHERTEXT_BYTES, NONCE_BYTES, UNIX_MINUTE_MS,
};

pub const MESSAGE_ROWS: TableName = TableName::new("message_rows");
pub const OPENED_MESSAGE_ROWS: TableName = TableName::new("opened_message_rows");
pub const SEALED_MESSAGE_ROWS: TableName = TableName::new("sealed_message_rows");
pub const MESSAGE_TOMBSTONE_ROWS: TableName = TableName::new("message_tombstone_rows");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedMessageRow {
    pub workspace_id: WorkspaceId,
    pub message_id: FactId,
    pub created_at_ms: u64,
    pub author_user_id: AuthorId,
    pub signer_id: SignerId,
    pub frontier_id: FrontierId,
    pub local_history_node_secret_id: FactId,
    pub expires_at_minute: u64,
    pub disappearing_setting_id: FactId,
    pub minute: u64,
    pub leaf_id: FactId,
    pub nonce: [u8; NONCE_BYTES],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRow {
    pub workspace_id: WorkspaceId,
    pub message_id: FactId,
    pub created_at_ms: u64,
    pub author_user_id: AuthorId,
    pub signer_id: SignerId,
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

pub fn sealed_message_row(input: SealedMessageRow) -> Result<TableRow, String> {
    let mut value = Vec::with_capacity(
        1 + 8 + 32 + 32 + 32 + 32 + 8 + 32 + 8 + 32 + NONCE_BYTES + 4 + CIPHERTEXT_BYTES,
    );
    value.push(1);
    value.extend_from_slice(&input.created_at_ms.to_be_bytes());
    value.extend_from_slice(&input.author_user_id);
    value.extend_from_slice(&input.signer_id);
    value.extend_from_slice(&input.frontier_id);
    value.extend_from_slice(&input.local_history_node_secret_id);
    value.extend_from_slice(&input.expires_at_minute.to_be_bytes());
    value.extend_from_slice(&input.disappearing_setting_id);
    value.extend_from_slice(&input.minute.to_be_bytes());
    value.extend_from_slice(&input.leaf_id);
    value.extend_from_slice(&input.nonce);
    let slot =
        FixedSlot::<CIPHERTEXT_BYTES>::new(&input.ciphertext).map_err(|err| format!("{err:?}"))?;
    let mut encoded = vec![0; 4 + CIPHERTEXT_BYTES];
    slot.encode(&mut encoded)
        .map_err(|err| format!("{err:?}"))?;
    value.extend_from_slice(&encoded);
    Ok(TableRow {
        table: SEALED_MESSAGE_ROWS,
        key: message_key(input.workspace_id, input.message_id),
        value,
    })
}

pub fn decode_sealed_message_row(key: &[u8], value: &[u8]) -> Result<SealedMessageRow, String> {
    let (workspace_id, message_id) = decode_message_key(key, "sealed message key")?;
    if value.len()
        != 1 + 8 + 32 + 32 + 32 + 32 + 8 + 32 + 8 + 32 + NONCE_BYTES + 4 + CIPHERTEXT_BYTES
        || value[0] != 1
    {
        return Err("invalid sealed message value".to_string());
    }
    let ciphertext_offset = 1 + 8 + 32 + 32 + 32 + 32 + 8 + 32 + 8 + 32 + NONCE_BYTES;
    Ok(SealedMessageRow {
        workspace_id,
        message_id,
        created_at_ms: u64::from_be_bytes(value[1..9].try_into().unwrap()),
        author_user_id: value[9..41].try_into().unwrap(),
        signer_id: value[41..73].try_into().unwrap(),
        frontier_id: value[73..105].try_into().unwrap(),
        local_history_node_secret_id: value[105..137].try_into().unwrap(),
        expires_at_minute: u64::from_be_bytes(value[137..145].try_into().unwrap()),
        disappearing_setting_id: value[145..177].try_into().unwrap(),
        minute: u64::from_be_bytes(value[177..185].try_into().unwrap()),
        leaf_id: value[185..217].try_into().unwrap(),
        nonce: value[217..241].try_into().unwrap(),
        ciphertext: FixedSlot::<CIPHERTEXT_BYTES>::decode(&value[ciphertext_offset..])
            .map_err(|err| format!("{err:?}"))?
            .bytes()
            .to_vec(),
    })
}

pub fn message_key(workspace_id: WorkspaceId, message_id: FactId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&message_id);
    key
}

pub fn message_row(input: MessageRow) -> TableRow {
    let mut value = Vec::with_capacity(113);
    value.push(1);
    value.extend_from_slice(&input.created_at_ms.to_be_bytes());
    value.extend_from_slice(&input.author_user_id);
    value.extend_from_slice(&input.signer_id);
    value.extend_from_slice(&input.minute.to_be_bytes());
    value.extend_from_slice(&input.leaf_id);
    TableRow {
        table: MESSAGE_ROWS,
        key: message_key(input.workspace_id, input.message_id),
        value,
    }
}

pub fn decode_message_row(key: &[u8], value: &[u8]) -> Result<MessageRow, String> {
    let (workspace_id, message_id) = decode_message_key(key, "message row key")?;
    if value.len() != 113 || value[0] != 1 {
        return Err("invalid message row value".to_string());
    }
    Ok(MessageRow {
        workspace_id,
        message_id,
        created_at_ms: u64::from_be_bytes(value[1..9].try_into().unwrap()),
        author_user_id: value[9..41].try_into().unwrap(),
        signer_id: value[41..73].try_into().unwrap(),
        minute: u64::from_be_bytes(value[73..81].try_into().unwrap()),
        leaf_id: value[81..113].try_into().unwrap(),
    })
}

pub fn opened_message_row(input: OpenedMessageRow) -> TableRow {
    let text = input.text.as_bytes();
    let mut value = Vec::with_capacity(1 + 8 + 32 + 32 + 4 + text.len());
    value.push(1);
    value.extend_from_slice(&input.created_at_ms.to_be_bytes());
    value.extend_from_slice(&input.author_user_id);
    value.extend_from_slice(&input.signer_id);
    value.extend_from_slice(&(text.len() as u32).to_be_bytes());
    value.extend_from_slice(text);
    TableRow {
        table: OPENED_MESSAGE_ROWS,
        key: message_key(input.workspace_id, input.message_id),
        value,
    }
}

pub fn decode_opened_message_row(key: &[u8], value: &[u8]) -> Result<OpenedMessageRow, String> {
    let (workspace_id, message_id) = decode_message_key(key, "opened message row key")?;
    if value.len() < 77 || value[0] != 1 {
        return Err("invalid opened message value".to_string());
    }
    let text_len = u32::from_be_bytes(value[73..77].try_into().unwrap()) as usize;
    if value.len() != 77 + text_len {
        return Err("opened message text length does not match value".to_string());
    }
    let text = String::from_utf8(value[77..].to_vec())
        .map_err(|err| format!("opened message text is not utf8: {err}"))?;
    Ok(OpenedMessageRow {
        workspace_id,
        message_id,
        created_at_ms: u64::from_be_bytes(value[1..9].try_into().unwrap()),
        author_user_id: value[9..41].try_into().unwrap(),
        signer_id: value[41..73].try_into().unwrap(),
        text,
    })
}

pub fn message_tombstone_row(
    workspace_id: WorkspaceId,
    message_id: FactId,
    author_user_id: AuthorId,
    created_at_ms: u64,
) -> TableRow {
    let mut value = Vec::with_capacity(41);
    value.push(1);
    value.extend_from_slice(&author_user_id);
    value.extend_from_slice(&(created_at_ms / UNIX_MINUTE_MS).to_be_bytes());
    TableRow {
        table: MESSAGE_TOMBSTONE_ROWS,
        key: message_key(workspace_id, message_id),
        value,
    }
}

pub fn decode_message_tombstone_row(
    key: &[u8],
    value: &[u8],
) -> Result<MessageTombstoneRow, String> {
    let (workspace_id, message_id) = decode_message_key(key, "message tombstone key")?;
    if value.len() != 41 || value[0] != 1 {
        return Err("invalid message tombstone value".to_string());
    }
    Ok(MessageTombstoneRow {
        workspace_id,
        message_id,
        author_user_id: value[1..33].try_into().unwrap(),
        authored_minute: u64::from_be_bytes(value[33..41].try_into().unwrap()),
    })
}

fn decode_message_key(key: &[u8], label: &str) -> Result<(WorkspaceId, FactId), String> {
    if key.len() != 64 {
        return Err(format!("{label} must be workspace id plus message id"));
    }
    Ok((
        key[..32].try_into().unwrap(),
        key[32..64].try_into().unwrap(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_message_row_round_trips_fixed_slot() {
        let input = SealedMessageRow {
            workspace_id: [1; 32],
            message_id: [2; 32],
            created_at_ms: 42_000,
            author_user_id: [3; 32],
            signer_id: [4; 32],
            frontier_id: [5; 32],
            local_history_node_secret_id: [6; 32],
            expires_at_minute: 99,
            disappearing_setting_id: [7; 32],
            minute: 42,
            leaf_id: [8; 32],
            nonce: [9; NONCE_BYTES],
            ciphertext: b"sealed".to_vec(),
        };
        let row = sealed_message_row(input.clone()).expect("row");

        assert_eq!(
            decode_sealed_message_row(&row.key, &row.value).expect("decode"),
            input
        );
    }

    #[test]
    fn message_tombstone_row_round_trips_workspace_key() {
        let row = message_tombstone_row([1; 32], [2; 32], [3; 32], 180_000);

        assert_eq!(row.key, message_key([1; 32], [2; 32]));
        assert_eq!(
            decode_message_tombstone_row(&row.key, &row.value).expect("decode"),
            MessageTombstoneRow {
                workspace_id: [1; 32],
                message_id: [2; 32],
                author_user_id: [3; 32],
                authored_minute: 3,
            }
        );
    }
}
