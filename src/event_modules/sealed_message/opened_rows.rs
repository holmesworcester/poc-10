//! Projection row layout for opened sealed-message content.

use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};

pub const OPENED_CONTENT_ROWS: TableName = TableName::new("opened_content_rows");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedContentRow {
    pub message_id: FactId,
    pub minute: u64,
    pub leaf_id: FactId,
}

pub fn opened_message_row(input: OpenedContentRow) -> TableRow {
    let mut value = Vec::with_capacity(41);
    value.push(1);
    value.extend_from_slice(&input.minute.to_be_bytes());
    value.extend_from_slice(&input.leaf_id);
    TableRow {
        table: OPENED_CONTENT_ROWS,
        key: input.message_id.to_vec(),
        value,
    }
}

pub fn decode_opened_message_row(key: &[u8], value: &[u8]) -> Result<OpenedContentRow, String> {
    if key.len() != 32 {
        return Err("opened content key must be a message id".to_string());
    }
    if value.len() != 41 || value[0] != 1 {
        return Err("invalid opened content value".to_string());
    }
    Ok(OpenedContentRow {
        message_id: key.try_into().unwrap(),
        minute: u64::from_be_bytes(value[1..9].try_into().unwrap()),
        leaf_id: value[9..41].try_into().unwrap(),
    })
}
