//! Fixed-width layout for cascade dependency fixtures.
//!
//! The cascade harness stores staged facts as raw bytes, so this layout keeps
//! the fixture canonical: one type byte, one timestamp, an explicit dependency
//! count, padded dependency slots, and a deterministic payload. Decoding
//! rejects nonzero padding so two byte strings cannot represent the same
//! dependency graph.

use crate::core::facts::FactId;

use super::fact::{CascadeTestFact, MAX_DEPS, PAYLOAD_BYTES};

pub const TYPE_CASCADE_TEST_FACT: u8 = 2;
pub const ENCODED_BYTES: usize = 1 + 8 + 1 + (MAX_DEPS * 32) + PAYLOAD_BYTES;

pub fn encode_fact(fact: &CascadeTestFact) -> Result<Vec<u8>, String> {
    if fact.dependencies.len() > MAX_DEPS {
        return Err("cascade fact dependency count exceeds fixed fields".to_string());
    }

    let mut out = vec![0; ENCODED_BYTES];
    out[0] = TYPE_CASCADE_TEST_FACT;
    out[1..9].copy_from_slice(&fact.timestamp.to_be_bytes());
    out[9] = fact.dependencies.len() as u8;
    let mut offset = 10;
    for idx in 0..MAX_DEPS {
        let dependency = fact.dependencies.get(idx).copied().unwrap_or([0; 32]);
        out[offset..offset + 32].copy_from_slice(&dependency);
        offset += 32;
    }
    out[offset..offset + PAYLOAD_BYTES].copy_from_slice(&fact.payload);
    Ok(out)
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
        dependencies,
        payload: bytes[offset..offset + PAYLOAD_BYTES].try_into().unwrap(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cascade_test_fact_roundtrips_fixed_width() {
        let fact = CascadeTestFact {
            timestamp: 42,
            dependencies: vec![[1; 32], [2; 32]],
            payload: [7; PAYLOAD_BYTES],
        };

        let bytes = encode_fact(&fact).expect("encode");

        assert_eq!(bytes.len(), ENCODED_BYTES);
        assert_eq!(decode_fact(&bytes).expect("decode"), fact);
    }
}
