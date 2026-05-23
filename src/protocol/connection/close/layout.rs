//! Stable bytes for connection-close facts.
//!
//! The close layout is fixed width:
//! `tag(1) || connection_id(32) || closed_at_ms(8)`. Encoding preserves this
//! exact shape so the close fact has a deterministic id.
//!
//! Change this file for close wire compatibility only. Context validation and
//! cleanup fanout belong in `project.rs`.

use crate::core::wire;

use super::fact::ConnectionCloseFact;

pub const TYPE_CONNECTION_CLOSE: u8 = 45;
pub const FACT_BYTES: usize = 1 + 32 + 8;

pub fn encode_fact(fact: &ConnectionCloseFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_CONNECTION_CLOSE, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.connection_id);
    wire::put_u64be(fact.closed_at_ms, &mut out[33..41]).map_err(wire_err)?;
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionCloseFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_CONNECTION_CLOSE {
        return Err("expected connection close fact".to_string());
    }
    let mut connection_id = [0; 32];
    connection_id.copy_from_slice(&bytes[1..33]);
    let closed_at_ms = wire::take_u64be(&bytes[33..41]).map_err(wire_err)?;
    Ok(ConnectionCloseFact {
        connection_id,
        closed_at_ms,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> ConnectionCloseFact {
        ConnectionCloseFact {
            connection_id: [1; 32],
            closed_at_ms: 2,
        }
    }

    #[test]
    fn connection_close_roundtrips_fixed_width() {
        let bytes = encode_fact(&fact()).expect("encode");
        assert_eq!(bytes.len(), FACT_BYTES);
        assert_eq!(decode_fact(&bytes).expect("decode"), fact());
    }

    #[test]
    fn rejects_wrong_tag_or_length() {
        let mut bytes = encode_fact(&fact()).expect("encode");
        bytes[0] = TYPE_CONNECTION_CLOSE.wrapping_add(1);
        assert!(decode_fact(&bytes).is_err());

        let mut short = encode_fact(&fact()).expect("encode");
        short.pop();
        assert!(decode_fact(&short).is_err());
    }
}
