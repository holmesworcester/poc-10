//! Sync compare projection rows.
//!
//! Rows are keyed by `connection_id || fact_id` so transit handlers can scan a
//! single connection's outstanding compare queries. The value stores the
//! timestamp range, the summary (count + fingerprint), and the
//! response-requested flag.

use crate::core::store::{TableName, TableRow};
use crate::core::wire;

use super::fact::{ConnectionId, SyncCompareFact};

pub const SYNC_COMPARE_ROWS: TableName = TableName::new("sync_compare_rows");
pub const ROW_VALUE_BYTES: usize = 8 + 8 + 8 + 32 + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncCompareRow {
    pub connection_id: ConnectionId,
    pub fact_id: [u8; 32],
    pub range_start: u64,
    pub range_end: u64,
    pub count: u64,
    pub fingerprint: [u8; 32],
    pub response_requested: bool,
}

pub fn sync_compare_key(connection_id: &ConnectionId, fact_id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(connection_id);
    key.extend_from_slice(fact_id);
    key
}

pub fn sync_compare_row(fact_id: [u8; 32], fact: &SyncCompareFact) -> Result<TableRow, String> {
    let mut value = vec![0; ROW_VALUE_BYTES];
    wire::put_u64be(fact.range.start, &mut value[0..8]).map_err(wire_err)?;
    wire::put_u64be(fact.range.end, &mut value[8..16]).map_err(wire_err)?;
    wire::put_u64be(fact.summary.count, &mut value[16..24]).map_err(wire_err)?;
    value[24..56].copy_from_slice(&fact.summary.fingerprint);
    wire::put_u8(u8::from(fact.response_requested), &mut value[56..57]).map_err(wire_err)?;
    Ok(TableRow {
        table: SYNC_COMPARE_ROWS,
        key: sync_compare_key(&fact.connection_id, &fact_id),
        value,
    })
}

pub fn decode_sync_compare_row(key: &[u8], value: &[u8]) -> Result<SyncCompareRow, String> {
    if key.len() != 64 {
        return Err("sync compare row key is malformed".to_string());
    }
    if value.len() != ROW_VALUE_BYTES {
        return Err("sync compare row value is malformed".to_string());
    }
    let mut connection_id = [0; 32];
    connection_id.copy_from_slice(&key[..32]);
    let mut fact_id = [0; 32];
    fact_id.copy_from_slice(&key[32..]);
    let range_start = wire::take_u64be(&value[0..8]).map_err(wire_err)?;
    let range_end = wire::take_u64be(&value[8..16]).map_err(wire_err)?;
    let count = wire::take_u64be(&value[16..24]).map_err(wire_err)?;
    let mut fingerprint = [0; 32];
    fingerprint.copy_from_slice(&value[24..56]);
    let response_requested = match wire::take_u8(&value[56..57]).map_err(wire_err)? {
        0 => false,
        1 => true,
        _ => return Err("sync compare row response flag is invalid".to_string()),
    };
    Ok(SyncCompareRow {
        connection_id,
        fact_id,
        range_start,
        range_end,
        count,
        fingerprint,
        response_requested,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
