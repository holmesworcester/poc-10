//! Read-only decoding for sync need-id projection rows.
//!
//! Query helpers are the only need-id module functions that inspect projected
//! row state directly. They never write, construct facts, project, or dispatch
//! intents.

use crate::core::facts::FactId;

use super::fact::ConnectionId;
use super::SYNC_NEED_ID_ROW_SCHEMA;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncNeedIdRow {
    pub connection_id: ConnectionId,
    pub fact_id: [u8; 32],
    pub requested_fact_id: FactId,
}

pub fn decode_sync_need_id_row(key: &[u8], value: &[u8]) -> Result<SyncNeedIdRow, String> {
    let key_fields = SYNC_NEED_ID_ROW_SCHEMA.decode_key(key)?;
    let value_fields = SYNC_NEED_ID_ROW_SCHEMA.decode_value(value)?;
    Ok(SyncNeedIdRow {
        connection_id: key_fields[0].as_bytes32("connection_id")?,
        fact_id: key_fields[1].as_bytes32("fact_id")?,
        requested_fact_id: value_fields[0].as_bytes32("requested_fact_id")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::sync::need_id::fact::SyncNeedIdFact;

    #[test]
    fn sync_need_id_row_roundtrips_through_schema() {
        let fact = SyncNeedIdFact {
            connection_id: [1; 32],
            fact_id: [2; 32],
        };
        let row = super::super::sync_need_id_row([9; 32], &fact).expect("sync need-id row");
        let decoded =
            decode_sync_need_id_row(&row.key, &row.value).expect("decode sync need-id row");
        assert_eq!(decoded.connection_id, [1; 32]);
        assert_eq!(decoded.fact_id, [9; 32]);
        assert_eq!(decoded.requested_fact_id, [2; 32]);
    }
}
