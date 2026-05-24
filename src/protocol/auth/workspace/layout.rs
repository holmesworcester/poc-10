//! Fixed-width layout for workspace facts and rows.
//!
//! Workspace names are fixed-slot UTF-8 strings with canonical zero padding so
//! fact ids and projected row values remain stable. This module owns that byte
//! shape. It should not grow membership or policy rules; those belong to user,
//! endpoint, auth key-material, and sync modules that refer back to the
//! workspace id.

use crate::core::crypto::{self, ED25519_SIGNATURE_BYTES};
use crate::core::wire;
use crate::core::wire::FixedText;

use super::fact::{WorkspaceFact, WorkspaceName, WorkspacePublicKey, WORKSPACE_NAME_BYTES};

pub const TYPE_WORKSPACE: u8 = 131;
pub const FACT_BYTES: usize = 1 + ROW_VALUE_BYTES;
pub const ROW_VALUE_BYTES: usize = 8 + 32 + WORKSPACE_NAME_BYTES + ED25519_SIGNATURE_BYTES;
const SIGNATURE_OFFSET: usize = FACT_BYTES - ED25519_SIGNATURE_BYTES;

pub fn encode_fact(fact: &WorkspaceFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_WORKSPACE, &mut out[0..1]).map_err(wire_err)?;
    encode_value_fields(fact, &mut out[1..])?;
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<WorkspaceFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_WORKSPACE {
        return Err("expected workspace fact".to_string());
    }
    decode_value_fields(&bytes[1..])
}

pub(crate) fn encode_value(fact: &WorkspaceFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; ROW_VALUE_BYTES];
    encode_value_fields(fact, &mut out)?;
    Ok(out)
}

pub(crate) fn decode_value(value: &[u8]) -> Result<WorkspaceFact, String> {
    decode_value_fields(value)
}

fn encode_value_fields(fact: &WorkspaceFact, out: &mut [u8]) -> Result<(), String> {
    wire::expect_len(out, ROW_VALUE_BYTES).map_err(wire_err)?;
    wire::put_u64be(fact.created_at_ms, &mut out[0..8]).map_err(wire_err)?;
    out[8..40].copy_from_slice(&fact.public_key);
    out[40..40 + WORKSPACE_NAME_BYTES].copy_from_slice(fact.name.padded_bytes());
    out[40 + WORKSPACE_NAME_BYTES..].copy_from_slice(&fact.signature);
    Ok(())
}

fn decode_value_fields(bytes: &[u8]) -> Result<WorkspaceFact, String> {
    wire::expect_len(bytes, ROW_VALUE_BYTES).map_err(wire_err)?;
    let created_at_ms = wire::take_u64be(&bytes[0..8]).map_err(wire_err)?;
    let mut public_key: WorkspacePublicKey = [0; 32];
    public_key.copy_from_slice(&bytes[8..40]);
    let name = decode_name(&bytes[40..40 + WORKSPACE_NAME_BYTES])?;
    let signature = bytes[40 + WORKSPACE_NAME_BYTES..]
        .try_into()
        .map_err(|_| "workspace signature slot has wrong length".to_string())?;
    Ok(WorkspaceFact {
        created_at_ms,
        public_key,
        name,
        signature,
    })
}

pub fn signing_bytes(fact: &WorkspaceFact) -> Result<Vec<u8>, String> {
    wire::canonical_with_zeroed_field(&encode_fact(fact)?, SIGNATURE_OFFSET..FACT_BYTES)
        .map_err(wire_err)
}

pub fn verify_signature(fact: &WorkspaceFact) -> Result<(), String> {
    crypto::ed25519_verify_canonical(
        &fact.public_key,
        &signing_bytes(fact)?,
        &fact.signature,
        "workspace",
    )
}

fn decode_name(bytes: &[u8]) -> Result<WorkspaceName, String> {
    let padded: [u8; WORKSPACE_NAME_BYTES] = bytes
        .try_into()
        .map_err(|_| "workspace name slot has wrong length".to_string())?;
    FixedText::from_padded(padded).map_err(wire_err)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> WorkspaceFact {
        WorkspaceFact {
            created_at_ms: 42,
            public_key: [7; 32],
            name: WorkspaceName::new("Engineering").expect("name"),
            signature: [8; ED25519_SIGNATURE_BYTES],
        }
    }

    #[test]
    fn workspace_fact_roundtrips_fixed_width() {
        let encoded = encode_fact(&fact()).expect("encode");

        assert_eq!(encoded.len(), FACT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }

    #[test]
    fn workspace_row_value_reuses_fact_payload_layout() {
        let value = encode_value(&fact()).expect("row value");
        let decoded = decode_value(&value).expect("decode row");

        assert_eq!(value.len(), ROW_VALUE_BYTES);
        assert_eq!(decoded.created_at_ms, 42);
        assert_eq!(decoded.name, "Engineering");
    }

    #[test]
    fn rejects_non_canonical_name_padding() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        let name_start = 1 + 8 + 32;
        encoded[name_start + "Engineering".len() + 1] = b'x';

        assert!(decode_fact(&encoded).is_err());
    }
}
