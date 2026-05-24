//! Fixed-width layout for sync shared-fact declarations.
//!
//! A shared-fact declaration is just a workspace id and fact id. Projection
//! turns it into a row that the sync index can query by connection. Keep this
//! layout id-only; the actual fact bytes stay in the core fact store.

use crate::core::wire;

use super::fact::SharedFact;

pub const TYPE_SHARED_FACT: u8 = 162;
pub const ENCODED_BYTES: usize = 1 + 32 + 32;

pub fn encode_fact(fact: &SharedFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; ENCODED_BYTES];
    wire::put_u8(TYPE_SHARED_FACT, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.fact_id);
    Ok(out)
}

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
