//! Fixed-width layout for the sync compare fact.
//!
//! Tag + connection id + range (u64,u64) + summary count (u64) + fingerprint
//! (32 bytes) + response flag (u8). The range is validated on decode so an
//! inverted range cannot make it past the codec.

use crate::core::wire;

use super::fact::{RangeSummary, SyncCompareFact, TimestampRange};

pub const TYPE_SYNC_COMPARE: u8 = 140;
pub const ENCODED_BYTES: usize = 1 + 32 + 8 + 8 + 8 + 32 + 1;

pub fn encode_fact(fact: &SyncCompareFact) -> Result<Vec<u8>, String> {
    if fact.range.start > fact.range.end {
        return Err("sync compare range is inverted".to_string());
    }
    let mut out = vec![0; ENCODED_BYTES];
    wire::put_u8(TYPE_SYNC_COMPARE, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.connection_id);
    wire::put_u64be(fact.range.start, &mut out[33..41]).map_err(wire_err)?;
    wire::put_u64be(fact.range.end, &mut out[41..49]).map_err(wire_err)?;
    wire::put_u64be(fact.summary.count, &mut out[49..57]).map_err(wire_err)?;
    out[57..89].copy_from_slice(&fact.summary.fingerprint);
    wire::put_u8(u8::from(fact.response_requested), &mut out[89..90]).map_err(wire_err)?;
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<SyncCompareFact, String> {
    wire::expect_len(bytes, ENCODED_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_SYNC_COMPARE {
        return Err("expected sync compare fact".to_string());
    }
    let mut connection_id = [0; 32];
    connection_id.copy_from_slice(&bytes[1..33]);
    let start = wire::take_u64be(&bytes[33..41]).map_err(wire_err)?;
    let end = wire::take_u64be(&bytes[41..49]).map_err(wire_err)?;
    if start > end {
        return Err("sync compare range is inverted".to_string());
    }
    let count = wire::take_u64be(&bytes[49..57]).map_err(wire_err)?;
    let mut fingerprint = [0; 32];
    fingerprint.copy_from_slice(&bytes[57..89]);
    let response_requested = match wire::take_u8(&bytes[89..90]).map_err(wire_err)? {
        0 => false,
        1 => true,
        _ => return Err("sync compare response flag is invalid".to_string()),
    };
    Ok(SyncCompareFact {
        connection_id,
        range: TimestampRange { start, end },
        summary: RangeSummary { count, fingerprint },
        response_requested,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> SyncCompareFact {
        SyncCompareFact {
            connection_id: [4; 32],
            range: TimestampRange {
                start: 10,
                end: 20,
            },
            summary: RangeSummary {
                count: 3,
                fingerprint: [7; 32],
            },
            response_requested: true,
        }
    }

    #[test]
    fn sync_compare_roundtrips() {
        let bytes = encode_fact(&fact()).expect("encode");
        assert_eq!(bytes.len(), ENCODED_BYTES);
        assert_eq!(decode_fact(&bytes).expect("decode"), fact());
    }

    #[test]
    fn rejects_inverted_range_on_decode() {
        let mut bytes = encode_fact(&fact()).expect("encode");
        // Swap start/end bytes to make start > end.
        bytes[33..41].copy_from_slice(&u64::MAX.to_be_bytes());
        bytes[41..49].copy_from_slice(&0u64.to_be_bytes());
        assert!(decode_fact(&bytes).is_err());
    }

    #[test]
    fn rejects_invalid_response_flag() {
        let mut bytes = encode_fact(&fact()).expect("encode");
        bytes[89] = 2;
        assert!(decode_fact(&bytes).is_err());
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut bytes = encode_fact(&fact()).expect("encode");
        bytes[0] = TYPE_SYNC_COMPARE.wrapping_add(1);
        assert!(decode_fact(&bytes).is_err());
    }

    #[test]
    fn rejects_truncated_or_extended_bytes() {
        let bytes = encode_fact(&fact()).expect("encode");
        let mut short = bytes.clone();
        short.pop();
        assert!(decode_fact(&short).is_err());
        let mut long = bytes;
        long.push(0);
        assert!(decode_fact(&long).is_err());
    }
}
