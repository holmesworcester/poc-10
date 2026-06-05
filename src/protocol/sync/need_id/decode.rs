//! Byte decoding for the sync need-id fact.
//!
//! Decoding proves only the fixed layout: tag, length, and field order.

use crate::core::wire;

use super::encode::{ENCODED_BYTES, TYPE_SYNC_NEED_ID};
use super::fact::SyncNeedIdFact;

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = SyncNeedIdFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact(fact.body())
    }
}

pub fn decode_fact(bytes: &[u8]) -> Result<SyncNeedIdFact, String> {
    wire::expect_len(bytes, ENCODED_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_SYNC_NEED_ID {
        return Err("expected sync need-id fact".to_string());
    }
    let mut connection_id = [0; 32];
    connection_id.copy_from_slice(&bytes[1..33]);
    let mut fact_id = [0; 32];
    fact_id.copy_from_slice(&bytes[33..65]);
    Ok(SyncNeedIdFact {
        connection_id,
        fact_id,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::sync::need_id::encode::{encode_fact, ENCODED_BYTES};

    fn fact() -> SyncNeedIdFact {
        SyncNeedIdFact {
            connection_id: [4; 32],
            fact_id: [8; 32],
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
