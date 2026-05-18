//! Fixed-width layouts for sealed-message target facts.

use crate::core::wire;

use super::fact::{
    MessageDeletionFact, SealedMessageFact, SecretNodeFact, SignerPubkeyFact, CIPHERTEXT_BYTES,
    NONCE_BYTES,
};

pub const TYPE_SEALED_MESSAGE: u8 = 140;
pub const TYPE_SIGNER_PUBKEY: u8 = 141;
pub const TYPE_SECRET_NODE: u8 = 142;
pub const TYPE_MESSAGE_DELETION: u8 = 143;

pub const SEALED_MESSAGE_BYTES: usize =
    1 + 32 + 8 + 32 + 32 + 32 + 32 + 8 + 32 + 8 + 32 + NONCE_BYTES + 4 + CIPHERTEXT_BYTES;
pub const SIGNER_PUBKEY_BYTES: usize = 1 + 32 + 32;
pub const SECRET_NODE_BYTES: usize = 1 + 32 + 32 + 8 + 8 + 1 + 32;
pub const MESSAGE_DELETION_BYTES: usize = 1 + 32 + 8 + 32 + 32;

pub fn encode_sealed_message(fact: &SealedMessageFact) -> Result<Vec<u8>, String> {
    let mut out = wire::Writer::with_capacity(SEALED_MESSAGE_BYTES);
    out.u8(TYPE_SEALED_MESSAGE);
    out.fixed(&fact.workspace_id);
    out.u64be(fact.created_at_ms);
    out.fixed(&fact.author_user_id);
    out.fixed(&fact.signer_id);
    out.fixed(&fact.frontier_id);
    out.fixed(&fact.local_history_node_secret_id);
    out.u64be(fact.expires_at_minute);
    out.fixed(&fact.disappearing_setting_id);
    out.u64be(fact.minute);
    out.fixed(&fact.leaf_id);
    out.fixed(&fact.nonce);
    out.fixed_slot::<CIPHERTEXT_BYTES>(&fact.ciphertext)
        .map_err(wire_err)?;
    out.finish_exact(SEALED_MESSAGE_BYTES).map_err(wire_err)
}

pub fn decode_sealed_message(bytes: &[u8]) -> Result<SealedMessageFact, String> {
    let mut reader = wire::Reader::new(bytes);
    reader.expect_len(SEALED_MESSAGE_BYTES).map_err(wire_err)?;
    expect_tag(&mut reader, TYPE_SEALED_MESSAGE, "sealed message")?;
    let fact = SealedMessageFact {
        workspace_id: reader.array().map_err(wire_err)?,
        created_at_ms: reader.u64be().map_err(wire_err)?,
        author_user_id: reader.array().map_err(wire_err)?,
        signer_id: reader.array().map_err(wire_err)?,
        frontier_id: reader.array().map_err(wire_err)?,
        local_history_node_secret_id: reader.array().map_err(wire_err)?,
        expires_at_minute: reader.u64be().map_err(wire_err)?,
        disappearing_setting_id: reader.array().map_err(wire_err)?,
        minute: reader.u64be().map_err(wire_err)?,
        leaf_id: reader.array().map_err(wire_err)?,
        nonce: reader.array().map_err(wire_err)?,
        ciphertext: reader.fixed_slot::<CIPHERTEXT_BYTES>().map_err(wire_err)?,
    };
    reader.finish().map_err(wire_err)?;
    Ok(fact)
}

pub fn encode_signer_pubkey(fact: &SignerPubkeyFact) -> Result<Vec<u8>, String> {
    let mut out = wire::Writer::with_capacity(SIGNER_PUBKEY_BYTES);
    out.u8(TYPE_SIGNER_PUBKEY);
    out.fixed(&fact.signer_id);
    out.fixed(&fact.public_key);
    out.finish_exact(SIGNER_PUBKEY_BYTES).map_err(wire_err)
}

pub fn decode_signer_pubkey(bytes: &[u8]) -> Result<SignerPubkeyFact, String> {
    let mut reader = wire::Reader::new(bytes);
    reader.expect_len(SIGNER_PUBKEY_BYTES).map_err(wire_err)?;
    expect_tag(&mut reader, TYPE_SIGNER_PUBKEY, "signer pubkey")?;
    let fact = SignerPubkeyFact {
        signer_id: reader.array().map_err(wire_err)?,
        public_key: reader.array().map_err(wire_err)?,
    };
    reader.finish().map_err(wire_err)?;
    Ok(fact)
}

pub fn encode_message_deletion(fact: &MessageDeletionFact) -> Result<Vec<u8>, String> {
    let mut out = wire::Writer::with_capacity(MESSAGE_DELETION_BYTES);
    out.u8(TYPE_MESSAGE_DELETION);
    out.fixed(&fact.workspace_id);
    out.u64be(fact.created_at_ms);
    out.fixed(&fact.target_id);
    out.fixed(&fact.author_user_id);
    out.finish_exact(MESSAGE_DELETION_BYTES).map_err(wire_err)
}

pub fn decode_message_deletion(bytes: &[u8]) -> Result<MessageDeletionFact, String> {
    let mut reader = wire::Reader::new(bytes);
    reader
        .expect_len(MESSAGE_DELETION_BYTES)
        .map_err(wire_err)?;
    expect_tag(&mut reader, TYPE_MESSAGE_DELETION, "message deletion")?;
    let fact = MessageDeletionFact {
        workspace_id: reader.array().map_err(wire_err)?,
        created_at_ms: reader.u64be().map_err(wire_err)?,
        target_id: reader.array().map_err(wire_err)?,
        author_user_id: reader.array().map_err(wire_err)?,
    };
    reader.finish().map_err(wire_err)?;
    Ok(fact)
}

pub fn encode_secret_node(fact: &SecretNodeFact) -> Result<Vec<u8>, String> {
    if fact.start_minute > fact.end_minute {
        return Err("secret node range is inverted".to_string());
    }
    if fact.prefix_bytes > 32 {
        return Err("secret node prefix is too long".to_string());
    }

    let mut out = wire::Writer::with_capacity(SECRET_NODE_BYTES);
    out.u8(TYPE_SECRET_NODE);
    out.fixed(&fact.workspace_id);
    out.fixed(&fact.frontier_id);
    out.u64be(fact.start_minute);
    out.u64be(fact.end_minute);
    out.u8(fact.prefix_bytes);
    out.fixed(&fact.leaf_prefix);
    out.finish_exact(SECRET_NODE_BYTES).map_err(wire_err)
}

pub fn decode_secret_node(bytes: &[u8]) -> Result<SecretNodeFact, String> {
    let mut reader = wire::Reader::new(bytes);
    reader.expect_len(SECRET_NODE_BYTES).map_err(wire_err)?;
    expect_tag(&mut reader, TYPE_SECRET_NODE, "secret node")?;
    let fact = SecretNodeFact {
        workspace_id: reader.array().map_err(wire_err)?,
        frontier_id: reader.array().map_err(wire_err)?,
        start_minute: reader.u64be().map_err(wire_err)?,
        end_minute: reader.u64be().map_err(wire_err)?,
        prefix_bytes: reader.u8().map_err(wire_err)?,
        leaf_prefix: reader.array().map_err(wire_err)?,
    };
    reader.finish().map_err(wire_err)?;
    encode_secret_node(&fact)?;
    Ok(fact)
}

fn expect_tag(reader: &mut wire::Reader<'_>, expected: u8, label: &str) -> Result<(), String> {
    let actual = reader.u8().map_err(wire_err)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!("expected {label}"))
    }
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_message_roundtrips_fixed_width() {
        let fact = SealedMessageFact {
            workspace_id: [1; 32],
            created_at_ms: 42_000,
            author_user_id: [2; 32],
            signer_id: [3; 32],
            frontier_id: [4; 32],
            local_history_node_secret_id: [5; 32],
            expires_at_minute: u64::MAX,
            disappearing_setting_id: [6; 32],
            minute: 42,
            leaf_id: [7; 32],
            nonce: [8; NONCE_BYTES],
            ciphertext: b"sealed".to_vec(),
        };
        let encoded = encode_sealed_message(&fact).expect("encode");

        assert_eq!(encoded.len(), SEALED_MESSAGE_BYTES);
        assert_eq!(decode_sealed_message(&encoded).expect("decode"), fact);
    }

    #[test]
    fn message_deletion_roundtrips_created_timestamp() {
        let fact = MessageDeletionFact {
            workspace_id: [1; 32],
            created_at_ms: 42_000,
            target_id: [2; 32],
            author_user_id: [3; 32],
        };
        let encoded = encode_message_deletion(&fact).expect("encode deletion");

        assert_eq!(encoded.len(), MESSAGE_DELETION_BYTES);
        assert_eq!(decode_message_deletion(&encoded).expect("decode"), fact);
    }

    #[test]
    fn secret_node_rejects_inverted_range() {
        let fact = SecretNodeFact {
            workspace_id: [1; 32],
            frontier_id: [2; 32],
            start_minute: 50,
            end_minute: 40,
            prefix_bytes: 0,
            leaf_prefix: [0; 32],
        };

        assert!(encode_secret_node(&fact).is_err());
    }
}
