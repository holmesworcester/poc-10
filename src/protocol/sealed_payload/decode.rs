use crate::core::wire;

use super::encode::{SEALED_PAYLOAD_BYTES, TYPE_SEALED_PAYLOAD};
use super::fact::{validate_payload, SealedPayloadFact, CIPHERTEXT_BYTES, HEADER_BYTES};

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = SealedPayloadFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact(fact.body())
    }
}

pub fn decode_fact(bytes: &[u8]) -> Result<SealedPayloadFact, String> {
    let mut reader = wire::Reader::new(bytes);
    reader.expect_len(SEALED_PAYLOAD_BYTES).map_err(wire_err)?;
    reader.expect_u8(TYPE_SEALED_PAYLOAD).map_err(wire_err)?;
    let payload = SealedPayloadFact {
        format: reader.u32be().map_err(wire_err)?,
        algorithm: reader.u32be().map_err(wire_err)?,
        header: reader
            .fixed_slot_value::<HEADER_BYTES>()
            .map_err(wire_err)?,
        ciphertext: reader
            .fixed_slot_value::<CIPHERTEXT_BYTES>()
            .map_err(wire_err)?,
    };
    reader.finish().map_err(wire_err)?;
    validate_payload(&payload)?;
    Ok(payload)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::sealed_payload::fact::{PayloadCiphertext, PayloadHeader};

    fn payload() -> SealedPayloadFact {
        SealedPayloadFact {
            format: 1,
            algorithm: 1,
            header: PayloadHeader::new(b"nonce").expect("header"),
            ciphertext: PayloadCiphertext::new(b"ciphertext").expect("ciphertext"),
        }
    }

    #[test]
    fn sealed_payload_roundtrips_fixed_width() {
        let encoded =
            crate::protocol::sealed_payload::encode::encode_fact(&payload()).expect("encode");
        assert_eq!(encoded.len(), SEALED_PAYLOAD_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), payload());
    }

    #[test]
    fn rejects_empty_ciphertext() {
        let mut payload = payload();
        payload.ciphertext = PayloadCiphertext::new(b"").expect("empty slot");
        assert!(crate::protocol::sealed_payload::encode::encode_fact(&payload).is_err());
    }
}
