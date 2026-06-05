//! Byte decoding for sync range requests.
//!
//! Decoding proves only the fixed layout: tag, length, field order, and that
//! the range is not inverted. It does not decide whether the peer may receive
//! the range.

use crate::core::wire;

use super::encode::{encode_fact, ENCODED_BYTES, TYPE_SYNC_RANGE_REQUEST};
use super::fact::SyncRangeRequestFact;

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = SyncRangeRequestFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact(fact.body())
    }
}

pub fn decode_fact(bytes: &[u8]) -> Result<SyncRangeRequestFact, String> {
    wire::expect_len(bytes, ENCODED_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_SYNC_RANGE_REQUEST {
        return Err("expected sync range request".to_string());
    }
    let fact = SyncRangeRequestFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        connection_id: bytes[33..65].try_into().unwrap(),
        start: wire::take_u64be(&bytes[65..73]).map_err(wire_err)?,
        end: wire::take_u64be(&bytes[73..81]).map_err(wire_err)?,
    };
    encode_fact(&fact)?;
    Ok(fact)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::sync::range_request::encode::{encode_fact, ENCODED_BYTES};

    #[test]
    fn sync_range_request_roundtrips_fixed_width() {
        let fact = SyncRangeRequestFact {
            workspace_id: [1; 32],
            connection_id: [2; 32],
            start: 10,
            end: 20,
        };

        let encoded = encode_fact(&fact).expect("encode sync range request");

        assert_eq!(encoded.len(), ENCODED_BYTES);
        assert_eq!(
            decode_fact(&encoded).expect("decode sync range request"),
            fact
        );
    }
}
