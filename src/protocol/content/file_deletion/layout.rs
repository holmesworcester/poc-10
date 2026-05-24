//! Fixed-width layout for content-file-deletion target facts.
//!
//! Body shape:
//!   tag (u8)
//!   workspace_id (32)
//!   created_at_ms (u64be)
//!   target_file_id (32)
//!   author_user_id (32)

use crate::core::crypto::{self, ED25519_SIGNATURE_BYTES};
use crate::core::wire;

use super::fact::ContentFileDeletionFact;

pub const TYPE_CONTENT_FILE_DELETION: u8 = 53;

pub const CONTENT_FILE_DELETION_BYTES: usize =
    1 + 32 + 8 + 32 + 32 + 32 + 32 + ED25519_SIGNATURE_BYTES;
const SIGNATURE_OFFSET: usize = CONTENT_FILE_DELETION_BYTES - ED25519_SIGNATURE_BYTES;

pub fn encode_fact(fact: &ContentFileDeletionFact) -> Result<Vec<u8>, String> {
    let mut out = wire::Writer::with_capacity(CONTENT_FILE_DELETION_BYTES);
    out.u8(TYPE_CONTENT_FILE_DELETION);
    out.fixed(&fact.workspace_id);
    out.u64be(fact.created_at_ms);
    out.fixed(&fact.target_file_id);
    out.fixed(&fact.author_user_id);
    out.fixed(&fact.signer_id);
    out.fixed(&fact.signer_public_key);
    out.fixed(&fact.signature);
    out.finish_exact(CONTENT_FILE_DELETION_BYTES)
        .map_err(wire_err)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ContentFileDeletionFact, String> {
    let mut reader = wire::Reader::new(bytes);
    reader
        .expect_len(CONTENT_FILE_DELETION_BYTES)
        .map_err(wire_err)?;
    let tag = reader.u8().map_err(wire_err)?;
    if tag != TYPE_CONTENT_FILE_DELETION {
        return Err("expected content file deletion fact".to_string());
    }
    let fact = ContentFileDeletionFact {
        workspace_id: reader.array().map_err(wire_err)?,
        created_at_ms: reader.u64be().map_err(wire_err)?,
        target_file_id: reader.array().map_err(wire_err)?,
        author_user_id: reader.array().map_err(wire_err)?,
        signer_id: reader.array().map_err(wire_err)?,
        signer_public_key: reader.array().map_err(wire_err)?,
        signature: reader.array().map_err(wire_err)?,
    };
    reader.finish().map_err(wire_err)?;
    Ok(fact)
}

pub fn signing_bytes(fact: &ContentFileDeletionFact) -> Result<Vec<u8>, String> {
    wire::canonical_with_zeroed_field(
        &encode_fact(fact)?,
        SIGNATURE_OFFSET..CONTENT_FILE_DELETION_BYTES,
    )
    .map_err(wire_err)
}

pub fn verify_signature(fact: &ContentFileDeletionFact) -> Result<(), String> {
    crypto::ed25519_verify_canonical(
        &fact.signer_public_key,
        &signing_bytes(fact)?,
        &fact.signature,
        "content file deletion",
    )
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> ContentFileDeletionFact {
        ContentFileDeletionFact {
            workspace_id: [1; 32],
            created_at_ms: 9_000,
            target_file_id: [2; 32],
            author_user_id: [3; 32],
            signer_id: [9; 32],
            signer_public_key: [10; 32],
            signature: [11; ED25519_SIGNATURE_BYTES],
        }
    }

    #[test]
    fn content_file_deletion_roundtrips_fixed_width() {
        let encoded = encode_fact(&fact()).expect("encode");
        assert_eq!(encoded.len(), CONTENT_FILE_DELETION_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        encoded[0] = TYPE_CONTENT_FILE_DELETION.wrapping_add(1);
        assert!(decode_fact(&encoded).is_err());
    }
}
