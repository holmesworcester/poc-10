//! Byte decoding for endpoint-shared facts.
//!
//! Decoding proves only the fixed layout: tag, length, and field order. Id and
//! id checks live in `authenticate.rs`.

use crate::core::wire;
use crate::core::wire::FixedText;

use super::encode::{FACT_BYTES, TYPE_ENDPOINT_SHARED};
use super::fact::{
    EndpointDeviceName, EndpointRole, EndpointSharedFact, ENDPOINT_DEVICE_NAME_BYTES,
};

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = EndpointSharedFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact(fact.body())
    }
}

pub fn decode_fact(bytes: &[u8]) -> Result<EndpointSharedFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_ENDPOINT_SHARED {
        return Err("expected endpoint shared fact".to_string());
    }
    let created_at_ms = wire::take_u64be(&bytes[1..9]).map_err(wire_err)?;
    let mut workspace_id = [0; 32];
    workspace_id.copy_from_slice(&bytes[9..41]);
    let mut user_authority_fact_id = [0; 32];
    user_authority_fact_id.copy_from_slice(&bytes[41..73]);
    let mut endpoint_id = [0; 32];
    endpoint_id.copy_from_slice(&bytes[73..105]);
    let mut signing_public_key = [0; 32];
    signing_public_key.copy_from_slice(&bytes[105..137]);
    let endpoint_role = EndpointRole::from_u8(wire::take_u8(&bytes[137..138]).map_err(wire_err)?)?;
    let device_name = read_device_name(&bytes[138..138 + ENDPOINT_DEVICE_NAME_BYTES])?;
    let signer_start = 138 + ENDPOINT_DEVICE_NAME_BYTES;
    let mut signer_id = [0; 32];
    signer_id.copy_from_slice(&bytes[signer_start..signer_start + 32]);
    let mut signer_public_key = [0; 32];
    signer_public_key.copy_from_slice(&bytes[signer_start + 32..signer_start + 64]);
    Ok(EndpointSharedFact {
        created_at_ms,
        workspace_id,
        user_authority_fact_id,
        endpoint_id,
        signing_public_key,
        endpoint_role,
        device_name,
        signer_id,
        signer_public_key,
    })
}

fn read_device_name(bytes: &[u8]) -> Result<EndpointDeviceName, String> {
    let padded: [u8; ENDPOINT_DEVICE_NAME_BYTES] = bytes
        .try_into()
        .map_err(|_| "endpoint device name slot has wrong length".to_string())?;
    FixedText::from_padded(padded).map_err(wire_err)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::auth::endpoint_shared::encode::{encode_fact, FACT_BYTES};

    fn fact() -> EndpointSharedFact {
        EndpointSharedFact {
            created_at_ms: 66,
            workspace_id: [1; 32],
            user_authority_fact_id: [2; 32],
            endpoint_id: [3; 32],
            signing_public_key: [4; 32],
            endpoint_role: EndpointRole::Device,
            device_name: EndpointDeviceName::new("laptop").expect("device name"),
            signer_id: [6; 32],
            signer_public_key: [7; 32],
        }
    }

    #[test]
    fn endpoint_shared_fact_roundtrips() {
        let encoded = encode_fact(&fact()).expect("encode");
        assert_eq!(encoded.len(), FACT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }

    #[test]
    fn rejects_bad_type() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        encoded[0] = 0xff;
        assert_eq!(
            decode_fact(&encoded).expect_err("wrong type must fail"),
            "expected endpoint shared fact"
        );
    }

    #[test]
    fn rejects_nul_device_name() {
        assert_eq!(
            EndpointDeviceName::new("bad\0name").expect_err("NUL name must fail"),
            wire::WireError::InteriorNul { index: 3 }
        );
    }

    #[test]
    fn rejects_non_canonical_device_name_padding() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        let name_start = 138;
        encoded[name_start + "laptop".len() + 1] = b'x';
        assert_eq!(
            decode_fact(&encoded).expect_err("padding must fail"),
            "NonZeroPadding { index: 7 }"
        );
    }

    #[test]
    fn rejects_unknown_role() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        encoded[137] = 99;
        assert_eq!(
            decode_fact(&encoded).expect_err("bad role must fail"),
            "unknown endpoint role"
        );
    }
}
