//! Byte decoding for workspace facts.
//!
//! Decoding proves only the fixed layout: tag, length, field order, and
//! canonical name padding. Id checks live in `authenticate.rs`.

use crate::core::wire;
use crate::core::wire::FixedText;

use super::encode::{FACT_BYTES, PAYLOAD_BYTES, TYPE_WORKSPACE};
use super::fact::{WorkspaceFact, WorkspaceName, WorkspacePublicKey, WORKSPACE_NAME_BYTES};

pub fn decode_fact(bytes: &[u8]) -> Result<WorkspaceFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_WORKSPACE {
        return Err("expected workspace fact".to_string());
    }
    decode_payload_fields(&bytes[1..])
}

#[cfg(test)]
pub(crate) fn decode_payload(value: &[u8]) -> Result<WorkspaceFact, String> {
    decode_payload_fields(value)
}

fn decode_payload_fields(bytes: &[u8]) -> Result<WorkspaceFact, String> {
    wire::expect_len(bytes, PAYLOAD_BYTES).map_err(wire_err)?;
    let created_at_ms = wire::take_u64be(&bytes[0..8]).map_err(wire_err)?;
    let mut public_key: WorkspacePublicKey = [0; 32];
    public_key.copy_from_slice(&bytes[8..40]);
    let name = decode_name(&bytes[40..40 + WORKSPACE_NAME_BYTES])?;
    Ok(WorkspaceFact {
        created_at_ms,
        public_key,
        name,
    })
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
        }
    }

    #[test]
    fn workspace_fact_roundtrips_fixed_width() {
        let encoded =
            crate::protocol::auth::workspace::encode::encode_fact(&fact()).expect("encode");

        assert_eq!(encoded.len(), FACT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }

    #[test]
    fn workspace_payload_roundtrips_fixed_width() {
        let value =
            crate::protocol::auth::workspace::encode::encode_payload(&fact()).expect("payload");
        let decoded = decode_payload(&value).expect("decode payload");

        assert_eq!(value.len(), PAYLOAD_BYTES);
        assert_eq!(decoded.created_at_ms, 42);
        assert_eq!(decoded.name, "Engineering");
    }

    #[test]
    fn rejects_non_canonical_name_padding() {
        let mut encoded =
            crate::protocol::auth::workspace::encode::encode_fact(&fact()).expect("encode");
        let name_start = 1 + 8 + 32;
        encoded[name_start + "Engineering".len() + 1] = b'x';

        assert!(decode_fact(&encoded).is_err());
    }
}
