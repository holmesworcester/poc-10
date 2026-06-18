//! Canonical byte encoding for local protocol update facts.
//!
//! This file owns byte construction only: the fact tag, fixed field order, and
//! field widths. It does not authenticate, project, query, or schedule update
//! work.

use crate::core::wire;

use super::fact::UpdateFact;

pub const TYPE_VERSIONING_UPDATE: u8 = 175;
pub const UPDATE_FACT_BYTES: usize = 1 + 4 + 8;

pub fn encode_update_fact(update: UpdateFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; UPDATE_FACT_BYTES];
    wire::put_u8(TYPE_VERSIONING_UPDATE, &mut out[0..1]).map_err(wire_err)?;
    wire::put_u32be(update.protocol_version, &mut out[1..5]).map_err(wire_err)?;
    wire::put_u64be(update.applied_at_ms, &mut out[5..13]).map_err(wire_err)?;
    Ok(out)
}

pub fn decode_update_fact(bytes: &[u8]) -> Result<UpdateFact, String> {
    wire::expect_len(bytes, UPDATE_FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_VERSIONING_UPDATE {
        return Err("expected versioning update fact".to_string());
    }
    let protocol_version = wire::take_u32be(&bytes[1..5]).map_err(wire_err)?;
    let applied_at_ms = wire::take_u64be(&bytes[5..13]).map_err(wire_err)?;
    Ok(UpdateFact {
        protocol_version,
        applied_at_ms,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_fact_roundtrips_fixed_width() {
        let update = UpdateFact {
            protocol_version: 7,
            applied_at_ms: 123,
        };
        let encoded = encode_update_fact(update).expect("encode");
        assert_eq!(encoded.len(), UPDATE_FACT_BYTES);
        assert_eq!(decode_update_fact(&encoded).expect("decode"), update);
    }
}
