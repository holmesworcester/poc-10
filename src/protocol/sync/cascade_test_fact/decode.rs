//! Byte decoding for cascade dependency fixtures.
//!
//! Decoding proves only the fixed layout: type byte, length, dependency count,
//! and padded dependency slots. Decoding rejects nonzero padding so two byte
//! strings cannot represent the same dependency graph.

use crate::core::facts::FactId;

use super::encode::{ENCODED_BYTES, TYPE_CASCADE_TEST_FACT};
use super::fact::{CascadeDependencies, CascadeTestFact, MAX_DEPS, PAYLOAD_BYTES};

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = CascadeTestFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact(fact.body())
    }
}

pub fn decode_fact(bytes: &[u8]) -> Result<CascadeTestFact, String> {
    if bytes.len() != ENCODED_BYTES {
        return Err("cascade fact length mismatch".to_string());
    }
    if bytes[0] != TYPE_CASCADE_TEST_FACT {
        return Err("unknown cascade fact type".to_string());
    }

    let timestamp = u64::from_be_bytes(bytes[1..9].try_into().unwrap());
    let dependency_count = bytes[9] as usize;
    if dependency_count > MAX_DEPS {
        return Err("cascade fact dependency count exceeds fixed fields".to_string());
    }

    let mut dependencies = Vec::with_capacity(dependency_count);
    let mut offset = 10;
    for idx in 0..MAX_DEPS {
        let dependency: FactId = bytes[offset..offset + 32].try_into().unwrap();
        if idx < dependency_count {
            dependencies.push(dependency);
        } else if dependency != [0; 32] {
            return Err("cascade fact unused dependency field is nonzero".to_string());
        }
        offset += 32;
    }

    Ok(CascadeTestFact {
        timestamp,
        dependencies: CascadeDependencies::new(&dependencies)?,
        payload: bytes[offset..offset + PAYLOAD_BYTES].try_into().unwrap(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::sync::cascade_test_fact::encode::{encode_fact, ENCODED_BYTES};

    #[test]
    fn cascade_test_fact_roundtrips_fixed_width() {
        let fact = CascadeTestFact {
            timestamp: 42,
            dependencies: CascadeDependencies::new(&[[1; 32], [2; 32]]).expect("dependencies"),
            payload: [7; PAYLOAD_BYTES],
        };

        let bytes = encode_fact(&fact).expect("encode");

        assert_eq!(bytes.len(), ENCODED_BYTES);
        assert_eq!(decode_fact(&bytes).expect("decode"), fact);
    }
}
