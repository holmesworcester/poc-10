//! Fixed-width endpoint-shared fact and projection-row layout.
//!
//! Inner payload layout:
//!
//! ```text
//! type(1) || created_at_ms(8) || workspace_id(32)
//!   || user_authority_fact_id(32) || endpoint_id(32)
//!   || signing_public_key(32) || endpoint_role(1)
//!   || device_name_utf8_zero_padded(64)
//! ```
//!
//! The fact carries its own signature fields. Projection owns authority checks
//! against device-invite or invite-server context.

use crate::core::crypto::{self, ED25519_SIGNATURE_BYTES};
use crate::core::wire;
use crate::core::wire::FixedText;

use super::fact::{
    EndpointDeviceName, EndpointRole, EndpointSharedFact, ENDPOINT_DEVICE_NAME_BYTES,
};

pub const TYPE_ENDPOINT_SHARED: u8 = 135;
pub const FACT_BYTES: usize =
    1 + 8 + 32 + 32 + 32 + 32 + 1 + ENDPOINT_DEVICE_NAME_BYTES + 32 + 32 + ED25519_SIGNATURE_BYTES;
const SIGNATURE_OFFSET: usize = FACT_BYTES - ED25519_SIGNATURE_BYTES;
pub const ROW_VALUE_BYTES: usize = 8 + 32 + 32 + 1 + 32 + ENDPOINT_DEVICE_NAME_BYTES;

pub fn encode_fact(fact: &EndpointSharedFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_ENDPOINT_SHARED, &mut out[0..1]).map_err(wire_err)?;
    wire::put_u64be(fact.created_at_ms, &mut out[1..9]).map_err(wire_err)?;
    out[9..41].copy_from_slice(&fact.workspace_id);
    out[41..73].copy_from_slice(&fact.user_authority_fact_id);
    out[73..105].copy_from_slice(&fact.endpoint_id);
    out[105..137].copy_from_slice(&fact.signing_public_key);
    wire::put_u8(fact.endpoint_role.as_u8(), &mut out[137..138]).map_err(wire_err)?;
    write_device_name(
        &fact.device_name,
        &mut out[138..138 + ENDPOINT_DEVICE_NAME_BYTES],
    )?;
    let signer_start = 138 + ENDPOINT_DEVICE_NAME_BYTES;
    out[signer_start..signer_start + 32].copy_from_slice(&fact.signer_id);
    out[signer_start + 32..signer_start + 64].copy_from_slice(&fact.signer_public_key);
    out[signer_start + 64..signer_start + 64 + ED25519_SIGNATURE_BYTES]
        .copy_from_slice(&fact.signature);
    Ok(out)
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
    let mut signature = [0; ED25519_SIGNATURE_BYTES];
    signature
        .copy_from_slice(&bytes[signer_start + 64..signer_start + 64 + ED25519_SIGNATURE_BYTES]);
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
        signature,
    })
}

pub fn signing_bytes(fact: &EndpointSharedFact) -> Result<Vec<u8>, String> {
    wire::canonical_with_zeroed_field(&encode_fact(fact)?, SIGNATURE_OFFSET..FACT_BYTES)
        .map_err(wire_err)
}

pub fn verify_signature(fact: &EndpointSharedFact) -> Result<(), String> {
    crypto::ed25519_verify_canonical(
        &fact.signer_public_key,
        &signing_bytes(fact)?,
        &fact.signature,
        "endpoint shared",
    )
}

/// Encodes the projection row value:
/// `created_at(8) || endpoint_id(32) || signing_public_key(32)
///   || endpoint_role(1) || user_authority_fact_id(32)
///   || device_name(64)`.
pub(crate) fn encode_row_value(fact: &EndpointSharedFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; ROW_VALUE_BYTES];
    wire::put_u64be(fact.created_at_ms, &mut out[0..8]).map_err(wire_err)?;
    out[8..40].copy_from_slice(&fact.endpoint_id);
    out[40..72].copy_from_slice(&fact.signing_public_key);
    wire::put_u8(fact.endpoint_role.as_u8(), &mut out[72..73]).map_err(wire_err)?;
    out[73..105].copy_from_slice(&fact.user_authority_fact_id);
    write_device_name(&fact.device_name, &mut out[105..])?;
    Ok(out)
}

pub(crate) fn decode_row_value(value: &[u8]) -> Result<DecodedRowValue, String> {
    wire::expect_len(value, ROW_VALUE_BYTES).map_err(wire_err)?;
    let created_at_ms = wire::take_u64be(&value[0..8]).map_err(wire_err)?;
    let mut endpoint_id = [0; 32];
    endpoint_id.copy_from_slice(&value[8..40]);
    let mut signing_public_key = [0; 32];
    signing_public_key.copy_from_slice(&value[40..72]);
    let endpoint_role = EndpointRole::from_u8(wire::take_u8(&value[72..73]).map_err(wire_err)?)?;
    let mut user_authority_fact_id = [0; 32];
    user_authority_fact_id.copy_from_slice(&value[73..105]);
    let device_name = read_device_name(&value[105..])?;
    Ok(DecodedRowValue {
        created_at_ms,
        endpoint_id,
        signing_public_key,
        endpoint_role,
        user_authority_fact_id,
        device_name: device_name.to_string(),
    })
}

pub(crate) struct DecodedRowValue {
    pub created_at_ms: u64,
    pub endpoint_id: [u8; 32],
    pub signing_public_key: [u8; 32],
    pub endpoint_role: EndpointRole,
    pub user_authority_fact_id: [u8; 32],
    pub device_name: String,
}

fn write_device_name(name: &EndpointDeviceName, out: &mut [u8]) -> Result<(), String> {
    wire::expect_len(out, ENDPOINT_DEVICE_NAME_BYTES).map_err(wire_err)?;
    out.copy_from_slice(name.padded_bytes());
    Ok(())
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
            signature: [8; ED25519_SIGNATURE_BYTES],
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
    fn row_value_roundtrip() {
        let value = encode_row_value(&fact()).expect("row value");
        let decoded = decode_row_value(&value).expect("decode row");
        assert_eq!(decoded.created_at_ms, 66);
        assert_eq!(decoded.endpoint_id, [3; 32]);
        assert_eq!(decoded.signing_public_key, [4; 32]);
        assert_eq!(decoded.endpoint_role, EndpointRole::Device);
        assert_eq!(decoded.user_authority_fact_id, [2; 32]);
        assert_eq!(decoded.device_name, "laptop");
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
