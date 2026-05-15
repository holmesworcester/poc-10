//! Fixed-width layout for the sync have-id fact.
//!
//! Tag + connection id (32) + timestamp (u64) + advertised event id (32).

use crate::core::wire;

use super::fact::SyncHaveIdFact;

pub const TYPE_SYNC_HAVE_ID: u8 = 141;
pub const ENCODED_BYTES: usize = 1 + 32 + 8 + 32;

pub fn encode_fact(fact: &SyncHaveIdFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; ENCODED_BYTES];
    wire::put_u8(TYPE_SYNC_HAVE_ID, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.connection_id);
    wire::put_u64be(fact.timestamp, &mut out[33..41]).map_err(wire_err)?;
    out[41..73].copy_from_slice(&fact.event_id);
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<SyncHaveIdFact, String> {
    wire::expect_len(bytes, ENCODED_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_SYNC_HAVE_ID {
        return Err("expected sync have-id fact".to_string());
    }
    let mut connection_id = [0; 32];
    connection_id.copy_from_slice(&bytes[1..33]);
    let timestamp = wire::take_u64be(&bytes[33..41]).map_err(wire_err)?;
    let mut event_id = [0; 32];
    event_id.copy_from_slice(&bytes[41..73]);
    Ok(SyncHaveIdFact {
        connection_id,
        timestamp,
        event_id,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> SyncHaveIdFact {
        SyncHaveIdFact {
            connection_id: [4; 32],
            timestamp: 777,
            event_id: [8; 32],
        }
    }

    #[test]
    fn sync_have_id_roundtrips() {
        let bytes = encode_fact(&fact()).expect("encode");
        assert_eq!(bytes.len(), ENCODED_BYTES);
        assert_eq!(decode_fact(&bytes).expect("decode"), fact());
    }

    #[test]
    fn rejects_wrong_tag_and_length() {
        let mut bytes = encode_fact(&fact()).expect("encode");
        bytes[0] = TYPE_SYNC_HAVE_ID.wrapping_add(1);
        assert!(decode_fact(&bytes).is_err());

        let mut short = encode_fact(&fact()).expect("encode");
        short.pop();
        assert!(decode_fact(&short).is_err());
    }
}
