//! Sync need-id projection rows.
//!
//! Rows are keyed by `connection_id || fact_id`; the value stores the
//! requested fact id. Keeping the fact id in the key keeps repeated needs
//! for the same fact id distinct across compare rounds.

use crate::core::store::{TableName, TableRow};

use crate::core::facts::FactId;

use super::fact::{ConnectionId, SyncNeedIdFact};

pub const SYNC_NEED_ID_ROWS: TableName = TableName::new("sync_need_id_rows");
pub const ROW_VALUE_BYTES: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncNeedIdRow {
    pub connection_id: ConnectionId,
    pub fact_id: [u8; 32],
    pub requested_fact_id: FactId,
}

pub fn sync_need_id_key(connection_id: &ConnectionId, fact_id: &[u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(connection_id);
    key.extend_from_slice(fact_id);
    key
}

pub fn sync_need_id_row(row_fact_id: [u8; 32], fact: &SyncNeedIdFact) -> Result<TableRow, String> {
    let mut value = vec![0; ROW_VALUE_BYTES];
    value[0..32].copy_from_slice(&fact.fact_id);
    Ok(TableRow {
        table: SYNC_NEED_ID_ROWS,
        key: sync_need_id_key(&fact.connection_id, &row_fact_id),
        value,
    })
}

pub fn decode_sync_need_id_row(key: &[u8], value: &[u8]) -> Result<SyncNeedIdRow, String> {
    if key.len() != 64 {
        return Err("sync need-id row key is malformed".to_string());
    }
    if value.len() != ROW_VALUE_BYTES {
        return Err("sync need-id row value is malformed".to_string());
    }
    let mut connection_id = [0; 32];
    connection_id.copy_from_slice(&key[..32]);
    let mut fact_id = [0; 32];
    fact_id.copy_from_slice(&key[32..]);
    let mut requested_fact_id = [0; 32];
    requested_fact_id.copy_from_slice(&value[0..32]);
    Ok(SyncNeedIdRow {
        connection_id,
        fact_id,
        requested_fact_id,
    })
}
