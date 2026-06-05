//! Read-only decoding for sync have-id projection rows.
//!
//! Query helpers are the only have-id module functions that inspect projected
//! row state directly. They never write, construct facts, project, or dispatch
//! intents.

use crate::core::facts::FactId;

use super::fact::ConnectionId;
use super::SYNC_HAVE_ID_ROW_SCHEMA;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncHaveIdRow {
    pub connection_id: ConnectionId,
    pub fact_id: [u8; 32],
    pub timestamp: u64,
    pub advertised_fact_id: FactId,
}

pub fn decode_sync_have_id_row(key: &[u8], value: &[u8]) -> Result<SyncHaveIdRow, String> {
    let key_fields = SYNC_HAVE_ID_ROW_SCHEMA.decode_key(key)?;
    let value_fields = SYNC_HAVE_ID_ROW_SCHEMA.decode_value(value)?;
    Ok(SyncHaveIdRow {
        connection_id: key_fields[0].as_bytes32("connection_id")?,
        fact_id: key_fields[1].as_bytes32("fact_id")?,
        timestamp: value_fields[0].as_u64("timestamp")?,
        advertised_fact_id: value_fields[1].as_bytes32("advertised_fact_id")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::sync::have_id::fact::SyncHaveIdFact;

    #[test]
    fn sync_have_id_row_roundtrips_through_schema() {
        let fact = SyncHaveIdFact {
            connection_id: [1; 32],
            timestamp: 77,
            fact_id: [2; 32],
        };
        let row = super::super::sync_have_id_row([9; 32], &fact).expect("sync have-id row");
        let decoded =
            decode_sync_have_id_row(&row.key, &row.value).expect("decode sync have-id row");
        assert_eq!(decoded.connection_id, [1; 32]);
        assert_eq!(decoded.fact_id, [9; 32]);
        assert_eq!(decoded.timestamp, 77);
        assert_eq!(decoded.advertised_fact_id, [2; 32]);
    }
}
