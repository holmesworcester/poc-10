//! Byte decoding for received connection-frame observation facts.
//!
//! Decoding proves only the fixed layout: tag, length, field order, and that the
//! origin addr is canonical. Id checks live in `authenticate.rs`.

use crate::core::wire::{self, FixedLayout};
use crate::protocol::connection::fact_receipt::fact::normalize_origin_addr_bytes;
use crate::protocol::connection::fact_receipt::fact::OriginAddr;

use super::encode::{
    CONNECTION_FRAME_OBSERVATION_FACT_BYTES, FRAME_FACT_OFFSET, ORIGIN_OFFSET, RECEIVED_AT_OFFSET,
    TYPE_CONNECTION_FRAME_OBSERVATION,
};
use super::fact::ConnectionFrameObservationFact;

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = ConnectionFrameObservationFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact(fact.body())
    }
}

pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionFrameObservationFact, String> {
    wire::expect_len(bytes, CONNECTION_FRAME_OBSERVATION_FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_CONNECTION_FRAME_OBSERVATION {
        return Err("expected connection frame observation".to_string());
    }
    let origin_addr =
        OriginAddr::decode(&bytes[ORIGIN_OFFSET..RECEIVED_AT_OFFSET]).map_err(wire_err)?;
    let canonical_origin_addr = normalize_origin_addr_bytes(origin_addr.bytes())?;
    if canonical_origin_addr != origin_addr.bytes() {
        return Err("connection frame observation origin addr is not canonical".to_string());
    }
    Ok(ConnectionFrameObservationFact {
        frame_fact_id: bytes[FRAME_FACT_OFFSET..ORIGIN_OFFSET].try_into().unwrap(),
        origin_addr,
        received_at_local_ms: wire::take_u64be(
            &bytes[RECEIVED_AT_OFFSET..CONNECTION_FRAME_OBSERVATION_FACT_BYTES],
        )
        .map_err(wire_err)?,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::connection::frame_observation::encode::{
        encode_fact, CONNECTION_FRAME_OBSERVATION_FACT_BYTES,
    };

    #[test]
    fn connection_frame_observation_roundtrips_fixed_width() {
        let fact = ConnectionFrameObservationFact {
            frame_fact_id: [1; 32],
            origin_addr: OriginAddr::new(b"127.0.0.1:41001").expect("origin"),
            received_at_local_ms: 123,
        };

        let encoded = encode_fact(&fact).expect("encode");

        assert_eq!(encoded.len(), CONNECTION_FRAME_OBSERVATION_FACT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact);
    }

    #[test]
    fn connection_frame_observation_normalizes_origin_addr() {
        let fact = ConnectionFrameObservationFact {
            frame_fact_id: [1; 32],
            origin_addr: OriginAddr::new(b"127.0.0.1_41001").expect("origin"),
            received_at_local_ms: 123,
        };

        let decoded = decode_fact(&encode_fact(&fact).expect("encode")).expect("decode");

        assert_eq!(decoded.origin_addr.bytes(), b"127.0.0.1:41001");
    }
}
