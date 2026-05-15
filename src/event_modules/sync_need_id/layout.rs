//! Fixed-width layout for the sync need-id fact.
//!
//! Tag + connection id (32) + requested event id (32).

use crate::core::wire;

use super::fact::SyncNeedIdFact;

pub const TYPE_SYNC_NEED_ID: u8 = 142;
pub const ENCODED_BYTES: usize = 1 + 32 + 32;

pub fn encode_fact(fact: &SyncNeedIdFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; ENCODED_BYTES];
    wire::put_u8(TYPE_SYNC_NEED_ID, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.connection_id);
    out[33..65].copy_from_slice(&fact.event_id);
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<SyncNeedIdFact, String> {
    wire::expect_len(bytes, ENCODED_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_SYNC_NEED_ID {
        return Err("expected sync need-id fact".to_string());
    }
    let mut connection_id = [0; 32];
    connection_id.copy_from_slice(&bytes[1..33]);
    let mut event_id = [0; 32];
    event_id.copy_from_slice(&bytes[33..65]);
    Ok(SyncNeedIdFact {
        connection_id,
        event_id,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> SyncNeedIdFact {
        SyncNeedIdFact {
            connection_id: [4; 32],
            event_id: [8; 32],
        }
    }

    #[test]
    fn sync_need_id_roundtrips() {
        let bytes = encode_fact(&fact()).expect("encode");
        assert_eq!(bytes.len(), ENCODED_BYTES);
        assert_eq!(decode_fact(&bytes).expect("decode"), fact());
    }

    #[test]
    fn rejects_wrong_tag_and_length() {
        let mut bytes = encode_fact(&fact()).expect("encode");
        bytes[0] = TYPE_SYNC_NEED_ID.wrapping_add(1);
        assert!(decode_fact(&bytes).is_err());

        let mut short = encode_fact(&fact()).expect("encode");
        short.pop();
        assert!(decode_fact(&short).is_err());
    }
}
