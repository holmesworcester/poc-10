//! Fixed-width layout for content-message-deletion target facts.
//!
//! Body shape:
//!   tag (u8)
//!   workspace_id (32)
//!   created_at_ms (u64be)
//!   target_message_id (32)
//!   target_frontier_id (32)
//!   target_minute (u64be)
//!   author_user_id (32)

use crate::core::crypto::{self, ED25519_SIGNATURE_BYTES};
use crate::core::wire;

use super::fact::ContentMessageDeletionFact;

pub const TYPE_CONTENT_MESSAGE_DELETION: u8 = 51;

pub const CONTENT_MESSAGE_DELETION_BYTES: usize =
    1 + 32 + 8 + 32 + 32 + 8 + 32 + 32 + 32 + ED25519_SIGNATURE_BYTES;
const SIGNATURE_OFFSET: usize = CONTENT_MESSAGE_DELETION_BYTES - ED25519_SIGNATURE_BYTES;

pub fn encode_fact(fact: &ContentMessageDeletionFact) -> Result<Vec<u8>, String> {
    let mut out = wire::Writer::with_capacity(CONTENT_MESSAGE_DELETION_BYTES);
    out.u8(TYPE_CONTENT_MESSAGE_DELETION);
    out.fixed(&fact.workspace_id);
    out.u64be(fact.created_at_ms);
    out.fixed(&fact.target_message_id);
    out.fixed(&fact.target_frontier_id);
    out.u64be(fact.target_minute);
    out.fixed(&fact.author_user_id);
    out.fixed(&fact.signer_id);
    out.fixed(&fact.signer_public_key);
    out.fixed(&fact.signature);
    out.finish_exact(CONTENT_MESSAGE_DELETION_BYTES)
        .map_err(wire_err)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ContentMessageDeletionFact, String> {
    let mut reader = wire::Reader::new(bytes);
    reader
        .expect_len(CONTENT_MESSAGE_DELETION_BYTES)
        .map_err(wire_err)?;
    let tag = reader.u8().map_err(wire_err)?;
    if tag != TYPE_CONTENT_MESSAGE_DELETION {
        return Err("expected content message deletion fact".to_string());
    }
    let fact = ContentMessageDeletionFact {
        workspace_id: reader.array().map_err(wire_err)?,
        created_at_ms: reader.u64be().map_err(wire_err)?,
        target_message_id: reader.array().map_err(wire_err)?,
        target_frontier_id: reader.array().map_err(wire_err)?,
        target_minute: reader.u64be().map_err(wire_err)?,
        author_user_id: reader.array().map_err(wire_err)?,
        signer_id: reader.array().map_err(wire_err)?,
        signer_public_key: reader.array().map_err(wire_err)?,
        signature: reader.array().map_err(wire_err)?,
    };
    reader.finish().map_err(wire_err)?;
    Ok(fact)
}

pub fn signing_bytes(fact: &ContentMessageDeletionFact) -> Result<Vec<u8>, String> {
    wire::canonical_with_zeroed_field(
        &encode_fact(fact)?,
        SIGNATURE_OFFSET..CONTENT_MESSAGE_DELETION_BYTES,
    )
    .map_err(wire_err)
}

pub fn verify_signature(fact: &ContentMessageDeletionFact) -> Result<(), String> {
    crypto::ed25519_verify_canonical(
        &fact.signer_public_key,
        &signing_bytes(fact)?,
        &fact.signature,
        "content message deletion",
    )
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> ContentMessageDeletionFact {
        ContentMessageDeletionFact {
            workspace_id: [1; 32],
            created_at_ms: 9_000,
            target_message_id: [2; 32],
            target_frontier_id: [3; 32],
            target_minute: 7,
            author_user_id: [4; 32],
            signer_id: [9; 32],
            signer_public_key: [10; 32],
            signature: [11; ED25519_SIGNATURE_BYTES],
        }
    }

    #[test]
    fn content_message_deletion_roundtrips_fixed_width() {
        let encoded = encode_fact(&fact()).expect("encode");
        assert_eq!(encoded.len(), CONTENT_MESSAGE_DELETION_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        encoded[0] = TYPE_CONTENT_MESSAGE_DELETION.wrapping_add(1);
        assert!(decode_fact(&encoded).is_err());
    }
}
