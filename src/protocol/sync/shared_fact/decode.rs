//! Byte decoding for sync shared-fact declarations.
//!
//! Decoding proves only the fixed layout: tag, length, and field order. The
//! actual fact bytes stay in the core fact store.

use crate::core::wire;

use super::encode::{ENCODED_BYTES, TYPE_SHARED_FACT};
use super::fact::SharedFact;

pub fn decode_fact(bytes: &[u8]) -> Result<SharedFact, String> {
    wire::expect_len(bytes, ENCODED_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_SHARED_FACT {
        return Err("expected sync shared fact".to_string());
    }
    Ok(SharedFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        fact_id: bytes[33..65].try_into().unwrap(),
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::sync::shared_fact::encode::{encode_fact, ENCODED_BYTES};

    #[test]
    fn shared_fact_roundtrips_fixed_width() {
        let fact = SharedFact {
            workspace_id: [1; 32],
            fact_id: [2; 32],
        };

        let encoded = encode_fact(&fact).expect("encode shared fact");

        assert_eq!(encoded.len(), ENCODED_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode shared fact"), fact);
    }
}
