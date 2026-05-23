//! Sync have-id projection rows.
//!
//! Rows are keyed by `connection_id || fact_id` so connection::frame handlers can scan
//! all advertisements queued for a connection. The value stores the
//! timestamp and the advertised fact id; the fact id in the key keeps
//! distinct advertisements distinct even when the same fact id is
//! re-advertised from a later range compare.

use crate::core::store::{TableName, TableRow};
use crate::core::wire;

use crate::core::facts::FactId;

use super::fact::{ConnectionId, SyncHaveIdFact};

pub const SYNC_HAVE_ID_ROWS: TableName = TableName::new("sync_have_id_rows");
pub const ROW_VALUE_BYTES: usize = 8 + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncHaveIdRow {
    pub connection_id: ConnectionId,
    pub fact_id: [u8; 32],
    pub timestamp: u64,
    pub advertised_fact_id: FactId,
}

pub fn sync_have_id_key(connection_id: &ConnectionId, fact_id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(connection_id);
    key.extend_from_slice(fact_id);
    key
}

pub fn sync_have_id_row(row_fact_id: [u8; 32], fact: &SyncHaveIdFact) -> Result<TableRow, String> {
    let mut value = vec![0; ROW_VALUE_BYTES];
    wire::put_u64be(fact.timestamp, &mut value[0..8]).map_err(wire_err)?;
    value[8..40].copy_from_slice(&fact.fact_id);
    Ok(TableRow {
        table: SYNC_HAVE_ID_ROWS,
        key: sync_have_id_key(&fact.connection_id, &row_fact_id),
        value,
    })
}

pub fn decode_sync_have_id_row(key: &[u8], value: &[u8]) -> Result<SyncHaveIdRow, String> {
    if key.len() != 64 {
        return Err("sync have-id row key is malformed".to_string());
    }
    if value.len() != ROW_VALUE_BYTES {
        return Err("sync have-id row value is malformed".to_string());
    }
    let mut connection_id = [0; 32];
    connection_id.copy_from_slice(&key[..32]);
    let mut fact_id = [0; 32];
    fact_id.copy_from_slice(&key[32..]);
    let timestamp = wire::take_u64be(&value[0..8]).map_err(wire_err)?;
    let mut advertised_fact_id = [0; 32];
    advertised_fact_id.copy_from_slice(&value[8..40]);
    Ok(SyncHaveIdRow {
        connection_id,
        fact_id,
        timestamp,
        advertised_fact_id,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
