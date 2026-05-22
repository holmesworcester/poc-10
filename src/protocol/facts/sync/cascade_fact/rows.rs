//! Staging rows for synthetic cascade fact replay.
//!
//! Cascade generation writes encoded facts here instead of submitting them to
//! the runtime immediately. Replay then reads the rows by index, reverses the
//! order, and uses the stored bytes to test whether context wakeups can recover
//! a dependency graph that arrived in an intentionally hostile order.

use crate::core::store::{TableName, TableRow};

pub const CASCADE_STAGED_FACT_ROWS: TableName = TableName::new("cascade_staged_fact_rows");

pub fn staged_fact_key(index: u64) -> Vec<u8> {
    index.to_be_bytes().to_vec()
}

pub fn staged_fact_row(index: u64, fact_bytes: Vec<u8>) -> TableRow {
    TableRow {
        table: CASCADE_STAGED_FACT_ROWS,
        key: staged_fact_key(index),
        value: fact_bytes,
    }
}

pub fn decode_staged_fact_key(key: &[u8]) -> Result<u64, String> {
    if key.len() != 8 {
        return Err("cascade staged fact key length mismatch".to_string());
    }
    Ok(u64::from_be_bytes(key.try_into().unwrap()))
}
