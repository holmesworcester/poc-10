//! Read-only decoding for sync compare projection rows.
//!
//! Query helpers are the only compare module functions that inspect projected
//! row state directly. They never write, construct facts, project, or dispatch
//! intents.

use super::fact::ConnectionId;
use super::SYNC_COMPARE_ROW_SCHEMA;

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

pub fn decode_sync_compare_row(key: &[u8], value: &[u8]) -> Result<SyncCompareRow, String> {
    let key_fields = SYNC_COMPARE_ROW_SCHEMA.decode_key(key)?;
    let value_fields = SYNC_COMPARE_ROW_SCHEMA.decode_value(value)?;
    let response_requested = match value_fields[4].as_u8("response_requested")? {
        0 => false,
        1 => true,
        _ => return Err("sync compare row response flag is invalid".to_string()),
    };
    Ok(SyncCompareRow {
        connection_id: key_fields[0].as_bytes32("connection_id")?,
        fact_id: key_fields[1].as_bytes32("fact_id")?,
        range_start: value_fields[0].as_u64("range_start")?,
        range_end: value_fields[1].as_u64("range_end")?,
        count: value_fields[2].as_u64("count")?,
        fingerprint: value_fields[3].as_bytes32("fingerprint")?,
        response_requested,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::sync::compare::fact::{RangeSummary, SyncCompareFact, TimestampRange};

    #[test]
    fn sync_compare_row_roundtrips_through_schema() {
        let fact = SyncCompareFact {
            connection_id: [1; 32],
            range: TimestampRange { start: 11, end: 22 },
            summary: RangeSummary {
                count: 33,
                fingerprint: [4; 32],
            },
            response_requested: true,
        };
        let row = super::super::sync_compare_row([9; 32], &fact).expect("sync compare row");
        let decoded =
            decode_sync_compare_row(&row.key, &row.value).expect("decode sync compare row");
        assert_eq!(decoded.connection_id, [1; 32]);
        assert_eq!(decoded.fact_id, [9; 32]);
        assert_eq!(decoded.range_start, 11);
        assert_eq!(decoded.range_end, 22);
        assert_eq!(decoded.count, 33);
        assert_eq!(decoded.fingerprint, [4; 32]);
        assert!(decoded.response_requested);
    }
}
