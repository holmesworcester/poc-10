//! Fixed-width layout for content-message target facts.
//!
//! Body shape:
//!   tag (u8)
//!   workspace_id (32)
//!   created_at_ms (u64be)
//!   author_user_id (32)
//!   signer_id (32)
//!   frontier_id (32)
//!   local_history_node_secret_id (32)
//!   expires_at_minute (u64be)
//!   retention_policy_id (32)
//!   minute (u64be)
//!   nonce (24)
//!   ciphertext (fixed slot)

use crate::core::wire;

use super::fact::{ContentMessageFact, CIPHERTEXT_BYTES, NONCE_BYTES};

pub const TYPE_CONTENT_MESSAGE: u8 = 50;

pub const CONTENT_MESSAGE_BYTES: usize =
    1 + 32 + 8 + 32 + 32 + 32 + 32 + 8 + 32 + 8 + NONCE_BYTES + 4 + CIPHERTEXT_BYTES;

pub fn encode_fact(fact: &ContentMessageFact) -> Result<Vec<u8>, String> {
    let mut out = wire::Writer::with_capacity(CONTENT_MESSAGE_BYTES);
    out.u8(TYPE_CONTENT_MESSAGE);
    out.fixed(&fact.workspace_id);
    out.u64be(fact.created_at_ms);
    out.fixed(&fact.author_user_id);
    out.fixed(&fact.signer_id);
    out.fixed(&fact.frontier_id);
    out.fixed(&fact.local_history_node_secret_id);
    out.u64be(fact.expires_at_minute);
    out.fixed(&fact.retention_policy_id);
    out.u64be(fact.minute);
    out.fixed(&fact.nonce);
    out.fixed_slot::<CIPHERTEXT_BYTES>(&fact.ciphertext)
        .map_err(wire_err)?;
    out.finish_exact(CONTENT_MESSAGE_BYTES).map_err(wire_err)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ContentMessageFact, String> {
    let mut reader = wire::Reader::new(bytes);
    reader.expect_len(CONTENT_MESSAGE_BYTES).map_err(wire_err)?;
    let tag = reader.u8().map_err(wire_err)?;
    if tag != TYPE_CONTENT_MESSAGE {
        return Err("expected content message fact".to_string());
    }
    let fact = ContentMessageFact {
        workspace_id: reader.array().map_err(wire_err)?,
        created_at_ms: reader.u64be().map_err(wire_err)?,
        author_user_id: reader.array().map_err(wire_err)?,
        signer_id: reader.array().map_err(wire_err)?,
        frontier_id: reader.array().map_err(wire_err)?,
        local_history_node_secret_id: reader.array().map_err(wire_err)?,
        expires_at_minute: reader.u64be().map_err(wire_err)?,
        retention_policy_id: reader.array().map_err(wire_err)?,
        minute: reader.u64be().map_err(wire_err)?,
        nonce: reader.array().map_err(wire_err)?,
        ciphertext: reader.fixed_slot::<CIPHERTEXT_BYTES>().map_err(wire_err)?,
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

    fn fact() -> ContentMessageFact {
        ContentMessageFact {
            workspace_id: [1; 32],
            created_at_ms: 180_000,
            author_user_id: [2; 32],
            signer_id: [3; 32],
            frontier_id: [4; 32],
            local_history_node_secret_id: [5; 32],
            expires_at_minute: u64::MAX,
            retention_policy_id: [6; 32],
            minute: 3,
            nonce: [8; NONCE_BYTES],
            ciphertext: b"sealed".to_vec(),
        }
    }

    #[test]
    fn content_message_roundtrips_fixed_width() {
        let encoded = encode_fact(&fact()).expect("encode");
        assert_eq!(encoded.len(), CONTENT_MESSAGE_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }

    #[test]
    fn rejects_wrong_tag() {
        let mut encoded = encode_fact(&fact()).expect("encode");
        encoded[0] = TYPE_CONTENT_MESSAGE.wrapping_add(1);
        assert!(decode_fact(&encoded).is_err());
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(decode_fact(&[TYPE_CONTENT_MESSAGE; 16]).is_err());
    }
}
