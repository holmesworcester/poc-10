//! Byte decoding for bundled connection-frame wire facts.
//!
//! Decoding proves only the fixed layout: tag, length, and the embedded frame
//! shape. Id checks live in `authenticate.rs`.

use crate::protocol::connection_frame_wire as wire;

use super::encode::{CONNECTION_FRAME_BUNDLE_FACT_BYTES, TYPE_CONNECTION_FRAME_BUNDLE};
use super::fact::ConnectionFrameBundleFact;

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = ConnectionFrameBundleFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact(fact.body())
    }
}

pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionFrameBundleFact, String> {
    if bytes.len() != CONNECTION_FRAME_BUNDLE_FACT_BYTES {
        return Err("connection frame bundle fact has wrong length".to_string());
    }
    let frame = wire::decode_frame_fact::<{ wire::CONNECTION_FRAME_BUNDLE_WIRE_BYTES }>(
        bytes,
        TYPE_CONNECTION_FRAME_BUNDLE,
        wire::CONNECTION_FRAME_SIZE_CLASS_BUNDLE,
    )?;
    Ok(ConnectionFrameBundleFact { frame })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::wire::FixedSlot;
    use crate::protocol::connection::frame_bundle::encode::{
        encode_fact, CONNECTION_FRAME_BUNDLE_FACT_BYTES,
    };

    #[test]
    fn connection_frame_bundle_fact_roundtrips_fixed_width() {
        let frame = wire::encode_frame_bytes(
            wire::CONNECTION_FRAME_SIZE_CLASS_BUNDLE,
            crate::core::wire::FixedBytes([1; 32]),
            crate::core::wire::FixedBytes([2; 24]),
            &[3; 32],
        )
        .expect("frame");
        let fact = ConnectionFrameBundleFact {
            frame: FixedSlot::new(&frame).expect("frame slot"),
        };

        let encoded = encode_fact(&fact).expect("encode");

        assert_eq!(encoded.len(), CONNECTION_FRAME_BUNDLE_FACT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact);
    }
}
