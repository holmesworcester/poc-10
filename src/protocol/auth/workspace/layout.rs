//! Fixed-width layout for workspace facts and rows.
//!
//! Workspace names are fixed-slot UTF-8 strings with canonical zero padding so
//! fact ids and projected row values remain stable. This module owns that byte
//! shape. It should not grow membership or policy rules; those belong to user,
//! endpoint, auth key-material, and sync modules that refer back to the
//! workspace id.

use crate::core::wire;
use crate::core::wire::FixedSlot;

use super::fact::{WorkspaceFact, WorkspacePublicKey, WORKSPACE_NAME_BYTES};

pub const TYPE_WORKSPACE: u8 = 131;
pub const FACT_BYTES: usize = 1 + ROW_VALUE_BYTES;
pub const ROW_VALUE_BYTES: usize = 8 + 32 + WORKSPACE_NAME_BYTES;

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
    if fact.name.as_bytes().contains(&0) {
        return Err("workspace name cannot contain NUL".to_string());
    }
    let name = FixedSlot::<WORKSPACE_NAME_BYTES>::new(fact.name.as_bytes()).map_err(wire_err)?;
    out[40..].copy_from_slice(name.padded_bytes());
    Ok(())
}

fn decode_value_fields(bytes: &[u8]) -> Result<WorkspaceFact, String> {
    wire::expect_len(bytes, ROW_VALUE_BYTES).map_err(wire_err)?;
    let created_at_ms = wire::take_u64be(&bytes[0..8]).map_err(wire_err)?;
    let mut public_key: WorkspacePublicKey = [0; 32];
    public_key.copy_from_slice(&bytes[8..40]);
    let name = decode_name(&bytes[40..])?;
    Ok(WorkspaceFact {
        created_at_ms,
        public_key,
        name,
    })
}

fn decode_name(bytes: &[u8]) -> Result<String, String> {
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    if bytes[end..].iter().any(|byte| *byte != 0) {
        return Err("workspace name has non-canonical padding".to_string());
    }
    std::str::from_utf8(&bytes[..end])
        .map_err(|_| "workspace name is not valid utf-8".to_string())
        .map(ToOwned::to_owned)
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
            name: "Engineering".to_string(),
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
