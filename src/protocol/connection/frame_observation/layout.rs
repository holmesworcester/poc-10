//! Stable bytes for received connection-frame observation facts.

use crate::core::wire::{self, FixedLayout, FixedSlot};
use crate::protocol::connection::fact_receipt::create::normalize_origin_addr_bytes;
use crate::protocol::connection::fact_receipt::fact::{OriginAddr, ORIGIN_ADDR_BYTES};

use super::fact::ConnectionFrameObservationFact;

pub const TYPE_CONNECTION_FRAME_OBSERVATION: u8 = 173;
pub const CONNECTION_FRAME_OBSERVATION_FACT_BYTES: usize =
    1 + 32 + FixedSlot::<ORIGIN_ADDR_BYTES>::LEN + wire::U64_BYTES;

const FRAME_FACT_OFFSET: usize = 1;
const ORIGIN_OFFSET: usize = FRAME_FACT_OFFSET + 32;
const RECEIVED_AT_OFFSET: usize = ORIGIN_OFFSET + FixedSlot::<ORIGIN_ADDR_BYTES>::LEN;

pub fn encode_fact(fact: &ConnectionFrameObservationFact) -> Result<Vec<u8>, String> {
    let origin_addr = normalize_origin_addr_bytes(fact.origin_addr.bytes())?;
    let origin_addr = OriginAddr::new(&origin_addr).map_err(wire_err)?;
    let mut out = vec![0; CONNECTION_FRAME_OBSERVATION_FACT_BYTES];
    wire::put_u8(TYPE_CONNECTION_FRAME_OBSERVATION, &mut out[0..1]).map_err(wire_err)?;
    out[FRAME_FACT_OFFSET..ORIGIN_OFFSET].copy_from_slice(&fact.frame_fact_id);
    origin_addr
        .encode(&mut out[ORIGIN_OFFSET..RECEIVED_AT_OFFSET])
        .map_err(wire_err)?;
    wire::put_u64be(
        fact.received_at_local_ms,
        &mut out[RECEIVED_AT_OFFSET..CONNECTION_FRAME_OBSERVATION_FACT_BYTES],
    )
    .map_err(wire_err)?;
    Ok(out)
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
