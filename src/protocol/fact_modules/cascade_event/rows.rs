use crate::core::store::{TableName, TableRow};

pub const CASCADE_STAGED_EVENT_ROWS: TableName = TableName::new("cascade_staged_event_rows");

pub fn staged_event_key(index: u64) -> Vec<u8> {
    index.to_be_bytes().to_vec()
}

pub fn staged_event_row(index: u64, event_bytes: Vec<u8>) -> TableRow {
    TableRow {
        table: CASCADE_STAGED_EVENT_ROWS,
        key: staged_event_key(index),
        value: event_bytes,
    }
}

pub fn decode_staged_event_key(key: &[u8]) -> Result<u64, String> {
    if key.len() != 8 {
        return Err("cascade staged event key length mismatch".to_string());
    }
    Ok(u64::from_be_bytes(key.try_into().unwrap()))
}
