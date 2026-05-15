//! Projection row layouts for sealed-message state.

use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};
use crate::core::wire::{FixedLayout, FixedSlot};

use super::fact::{FrontierId, SignerId, WorkspaceId, CIPHERTEXT_BYTES};

pub const MESSAGE_ROWS: TableName = TableName::new("message_rows");
pub const SEALED_MESSAGE_ROWS: TableName = TableName::new("sealed_message_rows");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedMessageRow {
    pub message_id: FactId,
    pub workspace_id: WorkspaceId,
    pub signer_id: SignerId,
    pub frontier_id: FrontierId,
    pub minute: u64,
    pub leaf_id: FactId,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRow {
    pub message_id: FactId,
    pub minute: u64,
    pub leaf_id: FactId,
}

pub fn sealed_message_row(input: SealedMessageRow) -> Result<TableRow, String> {
    let mut value = Vec::with_capacity(1 + 32 + 32 + 32 + 8 + 32 + 4 + CIPHERTEXT_BYTES);
    value.push(1);
    value.extend_from_slice(&input.workspace_id);
    value.extend_from_slice(&input.signer_id);
    value.extend_from_slice(&input.frontier_id);
    value.extend_from_slice(&input.minute.to_be_bytes());
    value.extend_from_slice(&input.leaf_id);
    let slot =
        FixedSlot::<CIPHERTEXT_BYTES>::new(&input.ciphertext).map_err(|err| format!("{err:?}"))?;
    let mut encoded = vec![0; 4 + CIPHERTEXT_BYTES];
    slot.encode(&mut encoded)
        .map_err(|err| format!("{err:?}"))?;
    value.extend_from_slice(&encoded);
    Ok(TableRow {
        table: SEALED_MESSAGE_ROWS,
        key: input.message_id.to_vec(),
        value,
    })
}

pub fn decode_sealed_message_row(key: &[u8], value: &[u8]) -> Result<SealedMessageRow, String> {
    if key.len() != 32 {
        return Err("sealed message key must be a message id".to_string());
    }
    if value.len() != 1 + 32 + 32 + 32 + 8 + 32 + 4 + CIPHERTEXT_BYTES || value[0] != 1 {
        return Err("invalid sealed message value".to_string());
    }
    Ok(SealedMessageRow {
        message_id: key.try_into().unwrap(),
        workspace_id: value[1..33].try_into().unwrap(),
        signer_id: value[33..65].try_into().unwrap(),
        frontier_id: value[65..97].try_into().unwrap(),
        minute: u64::from_be_bytes(value[97..105].try_into().unwrap()),
        leaf_id: value[105..137].try_into().unwrap(),
        ciphertext: FixedSlot::<CIPHERTEXT_BYTES>::decode(&value[137..])
            .map_err(|err| format!("{err:?}"))?
            .bytes()
            .to_vec(),
    })
}

pub fn message_row(input: MessageRow) -> TableRow {
    let mut value = Vec::with_capacity(41);
    value.push(1);
    value.extend_from_slice(&input.minute.to_be_bytes());
    value.extend_from_slice(&input.leaf_id);
    TableRow {
        table: MESSAGE_ROWS,
        key: input.message_id.to_vec(),
        value,
    }
}

pub fn decode_message_row(key: &[u8], value: &[u8]) -> Result<MessageRow, String> {
    if key.len() != 32 {
        return Err("message row key must be a message id".to_string());
    }
    if value.len() != 41 || value[0] != 1 {
        return Err("invalid message row value".to_string());
    }
    Ok(MessageRow {
        message_id: key.try_into().unwrap(),
        minute: u64::from_be_bytes(value[1..9].try_into().unwrap()),
        leaf_id: value[9..41].try_into().unwrap(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_message_row_round_trips_fixed_slot() {
        let input = SealedMessageRow {
            message_id: [1; 32],
            workspace_id: [2; 32],
            signer_id: [3; 32],
            frontier_id: [4; 32],
            minute: 42,
            leaf_id: [5; 32],
            ciphertext: b"sealed".to_vec(),
        };
        let row = sealed_message_row(input.clone()).expect("row");

        assert_eq!(
            decode_sealed_message_row(&row.key, &row.value).expect("decode"),
            input
        );
    }
}
