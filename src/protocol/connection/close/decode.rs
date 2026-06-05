//! Byte decoding for connection-close facts.
//!
//! Decoding proves only the fixed layout: tag, length, and field order. Id
//! checks and context validation live in `authenticate.rs` and `project.rs`.

use crate::core::wire;

use super::encode::{FACT_BYTES, TYPE_CONNECTION_CLOSE};
use super::fact::ConnectionCloseFact;

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = ConnectionCloseFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact(fact.body())
    }
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
    use crate::protocol::connection::close::encode::{
        encode_fact, FACT_BYTES, TYPE_CONNECTION_CLOSE,
    };

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
