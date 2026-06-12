//! Byte decoding for signature evidence facts.

use crate::core::wire;

use super::encode::{SIGNATURE_FACT_BYTES, TYPE_SIGNATURE};
use super::fact::SignatureFact;

pub fn decode_fact(bytes: &[u8]) -> Result<SignatureFact, String> {
    let mut reader = wire::Reader::new(bytes);
    reader.expect_len(SIGNATURE_FACT_BYTES).map_err(wire_err)?;
    let tag = reader.u8().map_err(wire_err)?;
    if tag != TYPE_SIGNATURE {
        return Err("expected signature fact".to_string());
    }
    let fact = SignatureFact {
        workspace_id: reader.array().map_err(wire_err)?,
        created_at_ms: reader.u64be().map_err(wire_err)?,
        target_fact_id: reader.array().map_err(wire_err)?,
        signer_public_key: reader.array().map_err(wire_err)?,
        signature: reader.array().map_err(wire_err)?,
    };
    reader.finish().map_err(wire_err)?;
    Ok(fact)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signature_fact() -> SignatureFact {
        SignatureFact {
            workspace_id: [4; 32],
            created_at_ms: 123,
            target_fact_id: [1; 32],
            signer_public_key: [2; 32],
            signature: [3; crate::core::crypto::ED25519_SIGNATURE_BYTES],
        }
    }

    #[test]
    fn signature_fact_roundtrips_fixed_width() {
        let encoded = super::super::encode::encode_fact(&signature_fact()).expect("encode");
        assert_eq!(encoded.len(), SIGNATURE_FACT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), signature_fact());
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut encoded = super::super::encode::encode_fact(&signature_fact()).expect("encode");
        encoded[0] = TYPE_SIGNATURE.wrapping_add(1);
        assert!(decode_fact(&encoded).is_err());
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(decode_fact(&[TYPE_SIGNATURE; 8]).is_err());
    }
}
