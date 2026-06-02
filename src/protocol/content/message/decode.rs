//! Content-message decoding: canonical wire bytes / `Fact` → typed value, and
//! the encrypted-slot → text recovery.
//!
//! `decode_fact` checks tag, length, and canonical field shape and produces the
//! typed `ContentMessageFact`; `recover_text` reads message text back out of a
//! decrypted slot. The `FactCodec` lives here so the read pipeline and context
//! provision decode a context owner through one entry.

use crate::core::facts::Fact;
use crate::core::wire;

use super::fact::{
    ContentMessageFact, CIPHERTEXT_BYTES, CONTENT_MESSAGE_BYTES, MAX_TEXT_BYTES,
    PLAINTEXT_SLOT_BYTES, TEXT_LENGTH_PREFIX_BYTES, TYPE_CONTENT_MESSAGE,
};

/// Decode canonical content-message bytes into the typed fact.
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
        signer_public_key: reader.array().map_err(wire_err)?,
        frontier_id: reader.array().map_err(wire_err)?,
        local_history_node_secret_id: reader.array().map_err(wire_err)?,
        expires_at_minute: reader.u64be().map_err(wire_err)?,
        retention_policy_id: reader.array().map_err(wire_err)?,
        minute: reader.u64be().map_err(wire_err)?,
        nonce: reader.array().map_err(wire_err)?,
        ciphertext: reader
            .fixed_slot_value::<CIPHERTEXT_BYTES>()
            .map_err(wire_err)?,
        signature: reader.array().map_err(wire_err)?,
    };
    reader.finish().map_err(wire_err)?;
    Ok(fact)
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<ContentMessageFact, String> {
    decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = ContentMessageFact;

    fn decode_fact(fact: &Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}

/// Recover message text from a decrypted plaintext slot (length prefix + text).
pub fn recover_text(plaintext: &[u8]) -> Result<String, String> {
    if plaintext.len() != PLAINTEXT_SLOT_BYTES {
        return Err(format!(
            "plaintext slot is {} bytes, expected {PLAINTEXT_SLOT_BYTES}",
            plaintext.len()
        ));
    }
    let len = wire::take_u32be(&plaintext[..TEXT_LENGTH_PREFIX_BYTES])
        .map_err(|err| format!("{err:?}"))? as usize;
    if len > MAX_TEXT_BYTES {
        return Err("recovered text length out of range".to_string());
    }
    let bytes = &plaintext[TEXT_LENGTH_PREFIX_BYTES..TEXT_LENGTH_PREFIX_BYTES + len];
    String::from_utf8(bytes.to_vec()).map_err(|err| format!("text was not utf-8: {err}"))
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::content::message::encode::encode_fact;
    use crate::protocol::content::message::fact::{MessageCiphertext, NONCE_BYTES};

    fn fact() -> ContentMessageFact {
        ContentMessageFact {
            workspace_id: [1; 32],
            created_at_ms: 180_000,
            author_user_id: [2; 32],
            signer_id: [3; 32],
            signer_public_key: [9; 32],
            frontier_id: [4; 32],
            local_history_node_secret_id: [5; 32],
            expires_at_minute: u64::MAX,
            retention_policy_id: [6; 32],
            minute: 3,
            nonce: [8; NONCE_BYTES],
            ciphertext: MessageCiphertext::new(b"sealed").expect("ciphertext"),
            signature: [10; crate::core::crypto::ED25519_SIGNATURE_BYTES],
        }
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
