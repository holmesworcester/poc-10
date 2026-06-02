//! Content-message encoding: typed value → canonical wire bytes, plus the
//! signing and encryption byte transcripts.
//!
//! This file owns *what the bytes are*: the fixed-width fact encoding, the
//! signing transcript (`signing_bytes`), the AEAD associated data, the nonce
//! input, and the plaintext-slot padding. It is pure serialization — it performs
//! no cryptography, no id check, and no context lookups. `author.rs` calls these
//! to produce the bytes it signs/encrypts; `authenticate.rs` calls
//! `signing_bytes` to verify.

use crate::core::crypto::{self, XChaCha20Poly1305Nonce};
use crate::core::facts::FactId;
use crate::core::wire;

use super::fact::{
    ContentMessageFact, WorkspaceId, CONTENT_MESSAGE_BYTES, MAX_TEXT_BYTES, PLAINTEXT_SLOT_BYTES,
    SIGNATURE_OFFSET, TEXT_LENGTH_PREFIX_BYTES, TYPE_CONTENT_MESSAGE,
};

/// Encode a content-message fact into its canonical fixed-width wire bytes.
pub fn encode_fact(fact: &ContentMessageFact) -> Result<Vec<u8>, String> {
    let mut out = wire::Writer::with_capacity(CONTENT_MESSAGE_BYTES);
    out.u8(TYPE_CONTENT_MESSAGE);
    out.fixed(&fact.workspace_id);
    out.u64be(fact.created_at_ms);
    out.fixed(&fact.author_user_id);
    out.fixed(&fact.signer_id);
    out.fixed(&fact.signer_public_key);
    out.fixed(&fact.frontier_id);
    out.fixed(&fact.local_history_node_secret_id);
    out.u64be(fact.expires_at_minute);
    out.fixed(&fact.retention_policy_id);
    out.u64be(fact.minute);
    out.fixed(&fact.nonce);
    out.fixed_slot_value(&fact.ciphertext).map_err(wire_err)?;
    out.fixed(&fact.signature);
    out.finish_exact(CONTENT_MESSAGE_BYTES).map_err(wire_err)
}

/// The canonical bytes the author signs and `authenticate` verifies: the encoded
/// fact with the trailing signature field zeroed.
pub fn signing_bytes(fact: &ContentMessageFact) -> Result<Vec<u8>, String> {
    wire::canonical_with_zeroed_field(&encode_fact(fact)?, SIGNATURE_OFFSET..CONTENT_MESSAGE_BYTES)
        .map_err(wire_err)
}

/// AEAD associated data binding the ciphertext to its workspace, frontier, and
/// minute.
pub fn associated_data(workspace_id: WorkspaceId, frontier_id: FactId, minute: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 + 32 + 8);
    bytes.extend_from_slice(&workspace_id);
    bytes.extend_from_slice(&frontier_id);
    let mut minute_bytes = [0u8; 8];
    wire::put_u64be(minute, &mut minute_bytes).expect("eight-byte minute slot");
    bytes.extend_from_slice(&minute_bytes);
    bytes
}

/// Deterministic AEAD nonce derived from the workspace, signer, and timestamp.
pub fn deterministic_nonce(
    workspace_id: WorkspaceId,
    signer_id: FactId,
    created_at_ms: u64,
) -> XChaCha20Poly1305Nonce {
    let mut info = Vec::with_capacity(32 + 32 + 8);
    info.extend_from_slice(&workspace_id);
    info.extend_from_slice(&signer_id);
    let mut ts = [0u8; 8];
    wire::put_u64be(created_at_ms, &mut ts).expect("eight-byte timestamp slot");
    info.extend_from_slice(&ts);
    let hash = crypto::hash(&info);
    let mut nonce = [0u8; super::fact::NONCE_BYTES];
    nonce.copy_from_slice(&hash[..super::fact::NONCE_BYTES]);
    nonce
}

/// Pad message text into the fixed plaintext slot: a 4-byte length prefix
/// followed by the text and zero padding.
pub fn pad_plaintext(text: &[u8]) -> Result<Vec<u8>, String> {
    if text.len() > MAX_TEXT_BYTES {
        return Err("text too long for encrypted slot".to_string());
    }
    let mut buf = vec![0u8; PLAINTEXT_SLOT_BYTES];
    let len = u32::try_from(text.len()).expect("text length fits u32");
    wire::put_u32be(len, &mut buf[..TEXT_LENGTH_PREFIX_BYTES]).map_err(|err| format!("{err:?}"))?;
    buf[TEXT_LENGTH_PREFIX_BYTES..TEXT_LENGTH_PREFIX_BYTES + text.len()].copy_from_slice(text);
    Ok(buf)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::content::message::decode::decode_fact;

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
            nonce: [8; super::super::fact::NONCE_BYTES],
            ciphertext: super::super::fact::MessageCiphertext::new(b"sealed").expect("ciphertext"),
            signature: [10; crypto::ED25519_SIGNATURE_BYTES],
        }
    }

    #[test]
    fn content_message_roundtrips_fixed_width() {
        let encoded = encode_fact(&fact()).expect("encode");
        assert_eq!(encoded.len(), CONTENT_MESSAGE_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact());
    }
}
