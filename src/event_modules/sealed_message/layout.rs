//! Fixed-width layouts for sealed-message target facts.

use crate::core::wire;
use crate::core::wire::{FixedLayout, FixedSlot};

use super::fact::{
    MessageDeletionFact, SealedMessageFact, SecretNodeFact, SignerPubkeyFact, CIPHERTEXT_BYTES,
};

pub const TYPE_SEALED_MESSAGE: u8 = 140;
pub const TYPE_SIGNER_PUBKEY: u8 = 141;
pub const TYPE_SECRET_NODE: u8 = 142;
pub const TYPE_MESSAGE_DELETION: u8 = 143;

pub const SEALED_MESSAGE_BYTES: usize = 1 + 32 + 32 + 32 + 8 + 32 + 4 + CIPHERTEXT_BYTES;
pub const SIGNER_PUBKEY_BYTES: usize = 1 + 32 + 32;
pub const SECRET_NODE_BYTES: usize = 1 + 32 + 32 + 8 + 8 + 1 + 32;
pub const MESSAGE_DELETION_BYTES: usize = 1 + 32 + 32;

pub fn encode_sealed_message(fact: &SealedMessageFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; SEALED_MESSAGE_BYTES];
    wire::put_u8(TYPE_SEALED_MESSAGE, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.signer_id);
    out[65..97].copy_from_slice(&fact.frontier_id);
    wire::put_u64be(fact.minute, &mut out[97..105]).map_err(wire_err)?;
    out[105..137].copy_from_slice(&fact.leaf_id);
    FixedSlot::<CIPHERTEXT_BYTES>::new(&fact.ciphertext)
        .map_err(wire_err)?
        .encode(&mut out[137..])
        .map_err(wire_err)?;
    Ok(out)
}

pub fn decode_sealed_message(bytes: &[u8]) -> Result<SealedMessageFact, String> {
    wire::expect_len(bytes, SEALED_MESSAGE_BYTES).map_err(wire_err)?;
    expect_tag(bytes, TYPE_SEALED_MESSAGE, "sealed message")?;
    Ok(SealedMessageFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        signer_id: bytes[33..65].try_into().unwrap(),
        frontier_id: bytes[65..97].try_into().unwrap(),
        minute: wire::take_u64be(&bytes[97..105]).map_err(wire_err)?,
        leaf_id: bytes[105..137].try_into().unwrap(),
        ciphertext: FixedSlot::<CIPHERTEXT_BYTES>::decode(&bytes[137..])
            .map_err(wire_err)?
            .bytes()
            .to_vec(),
    })
}

pub fn encode_signer_pubkey(fact: &SignerPubkeyFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; SIGNER_PUBKEY_BYTES];
    wire::put_u8(TYPE_SIGNER_PUBKEY, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.signer_id);
    out[33..65].copy_from_slice(&fact.public_key);
    Ok(out)
}

pub fn decode_signer_pubkey(bytes: &[u8]) -> Result<SignerPubkeyFact, String> {
    wire::expect_len(bytes, SIGNER_PUBKEY_BYTES).map_err(wire_err)?;
    expect_tag(bytes, TYPE_SIGNER_PUBKEY, "signer pubkey")?;
    Ok(SignerPubkeyFact {
        signer_id: bytes[1..33].try_into().unwrap(),
        public_key: bytes[33..65].try_into().unwrap(),
    })
}

pub fn encode_message_deletion(fact: &MessageDeletionFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; MESSAGE_DELETION_BYTES];
    wire::put_u8(TYPE_MESSAGE_DELETION, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.target_id);
    Ok(out)
}

pub fn decode_message_deletion(bytes: &[u8]) -> Result<MessageDeletionFact, String> {
    wire::expect_len(bytes, MESSAGE_DELETION_BYTES).map_err(wire_err)?;
    expect_tag(bytes, TYPE_MESSAGE_DELETION, "message deletion")?;
    Ok(MessageDeletionFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        target_id: bytes[33..65].try_into().unwrap(),
    })
}

pub fn encode_secret_node(fact: &SecretNodeFact) -> Result<Vec<u8>, String> {
    if fact.start_minute > fact.end_minute {
        return Err("secret node range is inverted".to_string());
    }
    if fact.prefix_bytes > 32 {
        return Err("secret node prefix is too long".to_string());
    }

    let mut out = vec![0; SECRET_NODE_BYTES];
    wire::put_u8(TYPE_SECRET_NODE, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.frontier_id);
    wire::put_u64be(fact.start_minute, &mut out[65..73]).map_err(wire_err)?;
    wire::put_u64be(fact.end_minute, &mut out[73..81]).map_err(wire_err)?;
    out[81] = fact.prefix_bytes;
    out[82..114].copy_from_slice(&fact.leaf_prefix);
    Ok(out)
}

pub fn decode_secret_node(bytes: &[u8]) -> Result<SecretNodeFact, String> {
    wire::expect_len(bytes, SECRET_NODE_BYTES).map_err(wire_err)?;
    expect_tag(bytes, TYPE_SECRET_NODE, "secret node")?;
    let fact = SecretNodeFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        frontier_id: bytes[33..65].try_into().unwrap(),
        start_minute: wire::take_u64be(&bytes[65..73]).map_err(wire_err)?,
        end_minute: wire::take_u64be(&bytes[73..81]).map_err(wire_err)?,
        prefix_bytes: bytes[81],
        leaf_prefix: bytes[82..114].try_into().unwrap(),
    };
    encode_secret_node(&fact)?;
    Ok(fact)
}

fn expect_tag(bytes: &[u8], expected: u8, label: &str) -> Result<(), String> {
    let actual = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
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
            signer_id: [2; 32],
            frontier_id: [3; 32],
            minute: 42,
            leaf_id: [4; 32],
            ciphertext: b"sealed".to_vec(),
        };
        let encoded = encode_sealed_message(&fact).expect("encode");

        assert_eq!(encoded.len(), SEALED_MESSAGE_BYTES);
        assert_eq!(decode_sealed_message(&encoded).expect("decode"), fact);
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
