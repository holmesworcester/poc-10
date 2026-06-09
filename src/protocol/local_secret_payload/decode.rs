use crate::core::wire;

use super::encode::{LOCAL_SECRET_PAYLOAD_BYTES, TYPE_LOCAL_SECRET_PAYLOAD};
use super::fact::{validate_secret, LocalSecretPayloadFact, SECRET_BYTES};

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = LocalSecretPayloadFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact(fact.body())
    }
}

pub fn decode_fact(bytes: &[u8]) -> Result<LocalSecretPayloadFact, String> {
    let mut reader = wire::Reader::new(bytes);
    reader
        .expect_len(LOCAL_SECRET_PAYLOAD_BYTES)
        .map_err(wire_err)?;
    reader
        .expect_u8(TYPE_LOCAL_SECRET_PAYLOAD)
        .map_err(wire_err)?;
    let secret = LocalSecretPayloadFact {
        family: reader.u32be().map_err(wire_err)?,
        version: reader.u32be().map_err(wire_err)?,
        bytes: reader
            .fixed_slot_value::<SECRET_BYTES>()
            .map_err(wire_err)?,
    };
    reader.finish().map_err(wire_err)?;
    validate_secret(&secret)?;
    Ok(secret)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::local_secret_payload::fact::LocalSecretBytes;

    fn secret() -> LocalSecretPayloadFact {
        LocalSecretPayloadFact {
            family: 1,
            version: 1,
            bytes: LocalSecretBytes::new(b"secret").expect("secret bytes"),
        }
    }

    #[test]
    fn local_secret_payload_roundtrips_fixed_width() {
        let encoded =
            crate::protocol::local_secret_payload::encode::encode_fact(&secret()).unwrap();
        assert_eq!(encoded.len(), LOCAL_SECRET_PAYLOAD_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), secret());
    }

    #[test]
    fn rejects_empty_secret() {
        let mut secret = secret();
        secret.bytes = LocalSecretBytes::new(b"").expect("empty slot");
        assert!(crate::protocol::local_secret_payload::encode::encode_fact(&secret).is_err());
    }
}
