//! Commands for signed key-wrap events.
//!
//! Creation seals one existing local key-secret id for one recipient key under
//! one removal frontier, then returns a proposed shared event. The command owns
//! cryptographic construction of that event, but it does not publish recipient
//! keys, store rows, or run receiver-side derivation.

use crate::core::crypto::{self, Ed25519PrivateKey, X25519PublicKey};
use crate::protocol::event_modules::types::{event_id, EventId};
use crate::protocol::event_modules::worker::CommandOutput;
use crate::protocol::wire::Writer;

use super::super::{local_history_node_secret, local_key_secret};
use super::codec;
use super::types::{KeyWrapEvent, WrappedSecretKind};

/// Sanity guard: every named id in a key-wrap event is non-zero. The codec
/// is intentionally lenient on decode; this helper is shared between the
/// authoring path (called via `validate_id` on each input) and the receive
/// projector so a malformed peer event is rejected at projection time too.
pub(super) fn validate_event_ids(event: &KeyWrapEvent) -> Result<(), String> {
    for (name, id) in [
        ("key wrap workspace", &event.workspace_id),
        ("key wrap removal_frontier_id", &event.removal_frontier_id),
        ("key wrap wrapped_secret_id", &event.wrapped_secret_id),
        ("key wrap recipient_key_id", &event.recipient_key_id),
        ("key wrap sender public key", &event.sender_wrap_public_key),
    ] {
        if id.iter().all(|byte| *byte == 0) {
            return Err(format!("{name} cannot be empty"));
        }
    }
    match event.wrapped_secret_kind {
        WrappedSecretKind::FrontierRoot => {
            if event.range_start != 0
                || event.range_width != 0
                || event.bit_depth != 0
                || event.event_id_prefix != [0; 32]
                || event.wrapped_source_secret_id != [0; 32]
                || event.wrapped_tombstone_node_id != [0; 32]
            {
                return Err("frontier root key wrap target coordinate must be empty".to_string());
            }
        }
        WrappedSecretKind::HistoryNode => {
            validate_id(
                "key wrap wrapped_source_secret_id",
                &event.wrapped_source_secret_id,
            )?;
            validate_history_node_coordinate(
                event.range_start,
                event.range_width,
                event.bit_depth,
                event.event_id_prefix,
            )?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateKeyWrap {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub signer_endpoint_shared_id: EventId,
    pub signer_private_key: Ed25519PrivateKey,
    pub removal_frontier_id: EventId,
    pub wrapped_secret_kind: WrappedSecretKind,
    pub wrapped_secret_id: EventId,
    pub wrapped_source_secret_id: EventId,
    pub wrapped_tombstone_node_id: EventId,
    pub range_start: u64,
    pub range_width: u64,
    pub bit_depth: u16,
    pub event_id_prefix: EventId,
    pub key_secret: local_history_node_secret::types::HistoryNodeSecret,
    pub recipient_key_id: EventId,
    pub recipient_key: X25519PublicKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyWrapOutput {
    pub key_wrap_id: EventId,
    pub workspace_id: EventId,
    pub removal_frontier_id: EventId,
    pub wrapped_secret_kind: WrappedSecretKind,
    pub wrapped_secret_id: EventId,
    pub recipient_key_id: EventId,
}

pub fn create(input: CreateKeyWrap) -> Result<CommandOutput<KeyWrapOutput>, String> {
    validate_id("workspace_id", &input.workspace_id)?;
    validate_id(
        "signer_endpoint_shared_id",
        &input.signer_endpoint_shared_id,
    )?;
    validate_id("removal_frontier_id", &input.removal_frontier_id)?;
    validate_id("wrapped_secret_id", &input.wrapped_secret_id)?;
    validate_id("key_secret", &input.key_secret)?;
    validate_id("recipient_key_id", &input.recipient_key_id)?;
    validate_id("recipient_key", &input.recipient_key)?;
    validate_secret_commitment(&input)?;

    let sender_wrap_secret = deterministic_sender_wrap_secret(&input);
    let sender_wrap_public_key = crypto::x25519_public_key(&sender_wrap_secret);
    let nonce = deterministic_nonce(&input);
    let mut event = KeyWrapEvent {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        removal_frontier_id: input.removal_frontier_id,
        wrapped_secret_kind: input.wrapped_secret_kind,
        wrapped_secret_id: input.wrapped_secret_id,
        wrapped_source_secret_id: input.wrapped_source_secret_id,
        wrapped_tombstone_node_id: input.wrapped_tombstone_node_id,
        range_start: input.range_start,
        range_width: input.range_width,
        bit_depth: input.bit_depth,
        event_id_prefix: input.event_id_prefix,
        recipient_key_id: input.recipient_key_id,
        sender_wrap_public_key,
        nonce,
        ciphertext: [0; super::types::KEY_WRAP_CIPHERTEXT_BYTES],
    };
    let ciphertext = crypto::x25519_xchacha20poly1305_encrypt(
        &sender_wrap_secret,
        &input.recipient_key,
        codec::KEY_WRAP_PURPOSE,
        &codec::associated_data(&event, input.signer_endpoint_shared_id),
        &event.nonce,
        &input.key_secret,
    )?;
    event.ciphertext = ciphertext
        .try_into()
        .map_err(|_| "key wrap ciphertext length mismatch".to_string())?;

    let payload = codec::encode(&event);
    let envelope = codec::sign(
        input.signer_endpoint_shared_id,
        &input.signer_private_key,
        payload,
    );
    let bytes = codec::encode_signed(&envelope);
    let record = codec::signed_record_from_bytes(bytes)?;
    let value = KeyWrapOutput {
        key_wrap_id: event_id(&record.canonical_bytes),
        workspace_id: event.workspace_id,
        removal_frontier_id: event.removal_frontier_id,
        wrapped_secret_kind: event.wrapped_secret_kind,
        wrapped_secret_id: event.wrapped_secret_id,
        recipient_key_id: event.recipient_key_id,
    };
    Ok(CommandOutput::with_events(value, vec![record]))
}

fn validate_secret_commitment(input: &CreateKeyWrap) -> Result<(), String> {
    match input.wrapped_secret_kind {
        WrappedSecretKind::FrontierRoot => {
            if input.range_start != 0
                || input.range_width != 0
                || input.bit_depth != 0
                || input.event_id_prefix != [0; 32]
                || input.wrapped_source_secret_id != [0; 32]
                || input.wrapped_tombstone_node_id != [0; 32]
            {
                return Err("frontier root key wrap target coordinate must be empty".to_string());
            }
            let output = local_key_secret::commands::from_key_secret(
                input.workspace_id,
                input.removal_frontier_id,
                input.key_secret,
            )?;
            if output.value.local_key_secret_id != input.wrapped_secret_id {
                return Err("key wrap wrapped_secret_id does not match root key secret".to_string());
            }
        }
        WrappedSecretKind::HistoryNode => {
            validate_id("wrapped_source_secret_id", &input.wrapped_source_secret_id)?;
            validate_history_node_coordinate(
                input.range_start,
                input.range_width,
                input.bit_depth,
                input.event_id_prefix,
            )?;
        }
    }
    Ok(())
}

fn validate_id(name: &str, id: &EventId) -> Result<(), String> {
    if id.iter().all(|byte| *byte == 0) {
        return Err(format!("{name} cannot be empty"));
    }
    Ok(())
}

fn deterministic_sender_wrap_secret(input: &CreateKeyWrap) -> crypto::X25519PrivateKey {
    crypto::blake3_keyed_hash(
        &input.key_secret,
        b"topo key wrap sender x25519 v1",
        &deterministic_wrap_info(input),
    )
}

fn deterministic_nonce(input: &CreateKeyWrap) -> crypto::XChaCha20Poly1305Nonce {
    let full = crypto::blake3_keyed_hash(
        &input.key_secret,
        b"topo key wrap nonce v1",
        &deterministic_wrap_info(input),
    );
    full[..crypto::XCHACHA20_POLY1305_NONCE_BYTES]
        .try_into()
        .expect("nonce slice has fixed length")
}

fn deterministic_wrap_info(input: &CreateKeyWrap) -> Vec<u8> {
    let mut out = Writer::with_capacity(32 * 8 + 1 + 8 + 8 + 2 + 8);
    out.id(&input.workspace_id);
    out.u64(input.created_at_ms);
    out.id(&input.signer_endpoint_shared_id);
    out.id(&input.removal_frontier_id);
    out.u8(input.wrapped_secret_kind.as_u8());
    out.id(&input.wrapped_secret_id);
    out.id(&input.wrapped_source_secret_id);
    out.id(&input.wrapped_tombstone_node_id);
    out.u64(input.range_start);
    out.u64(input.range_width);
    out.u16(input.bit_depth);
    out.id(&input.event_id_prefix);
    out.id(&input.recipient_key_id);
    out.id(&input.recipient_key);
    out.finish()
}

fn validate_history_node_coordinate(
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    event_id_prefix: EventId,
) -> Result<(), String> {
    if range_width == 0 || !range_width.is_power_of_two() {
        return Err(
            "history-node key wrap range_width must be a non-zero power of two".to_string(),
        );
    }
    if range_start % range_width != 0 {
        return Err("history-node key wrap range_start must be aligned to range_width".to_string());
    }
    if bit_depth > local_history_node_secret::types::TRIE_LEAF_BIT_DEPTH {
        return Err("history-node key wrap bit_depth is out of range".to_string());
    }
    let expected =
        local_history_node_secret::types::mask_prefix_to_depth(event_id_prefix, bit_depth);
    if event_id_prefix != expected {
        return Err(
            "history-node key wrap event_id_prefix must be masked to bit_depth".to_string(),
        );
    }
    if range_width > 1
        && (bit_depth != local_history_node_secret::types::TIME_TREE_BIT_DEPTH
            || event_id_prefix != [0; 32])
    {
        return Err("history-node key wrap time ranges must have empty trie prefix".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::protocol::event_modules::encryption::local_recipient_key;
    use crate::protocol::event_modules::types::EventScope;

    use super::*;

    #[test]
    fn create_proposes_signed_shared_key_wrap_without_local_secret_dep() {
        let local_secret = local_key_secret::commands::from_key_secret([1; 32], [2; 32], [7; 32])
            .expect("local")
            .value;
        let recipient = local_recipient_key::commands::create([1; 32])
            .expect("recipient")
            .value;
        let output = create(CreateKeyWrap {
            workspace_id: [1; 32],
            created_at_ms: 10,
            signer_endpoint_shared_id: [3; 32],
            signer_private_key: [9; 32],
            removal_frontier_id: [2; 32],
            wrapped_secret_kind: WrappedSecretKind::FrontierRoot,
            wrapped_secret_id: local_secret.local_key_secret_id,
            wrapped_source_secret_id: [0; 32],
            wrapped_tombstone_node_id: [0; 32],
            range_start: 0,
            range_width: 0,
            bit_depth: 0,
            event_id_prefix: [0; 32],
            key_secret: local_secret.event.key_secret,
            recipient_key_id: [4; 32],
            recipient_key: recipient.recipient_key,
        })
        .expect("create wrap");

        assert_eq!(output.events.len(), 1);
        let record = output.events[0].record();
        assert_eq!(record.scope, EventScope::Shared);
        assert_eq!(record.workspace_id, Some([1; 32]));
        assert_eq!(
            record.dependencies,
            vec![[3; 32], [1; 32], [2; 32], [4; 32]]
        );
        assert!(!record
            .dependencies
            .contains(&local_secret.local_key_secret_id));
    }

    #[test]
    fn create_rejects_secret_commitment_mismatch() {
        let recipient = local_recipient_key::commands::create([1; 32])
            .expect("recipient")
            .value;
        let err = create(CreateKeyWrap {
            workspace_id: [1; 32],
            created_at_ms: 10,
            signer_endpoint_shared_id: [3; 32],
            signer_private_key: [9; 32],
            removal_frontier_id: [2; 32],
            wrapped_secret_kind: WrappedSecretKind::FrontierRoot,
            wrapped_secret_id: [8; 32],
            wrapped_source_secret_id: [0; 32],
            wrapped_tombstone_node_id: [0; 32],
            range_start: 0,
            range_width: 0,
            bit_depth: 0,
            event_id_prefix: [0; 32],
            key_secret: [7; 32],
            recipient_key_id: [4; 32],
            recipient_key: recipient.recipient_key,
        })
        .expect_err("mismatch must fail");

        assert_eq!(
            err,
            "key wrap wrapped_secret_id does not match root key secret"
        );
    }

    #[test]
    fn create_is_deterministic_for_same_wrap_edge() {
        let local_secret = local_key_secret::commands::from_key_secret([1; 32], [2; 32], [7; 32])
            .expect("local")
            .value;
        let recipient = local_recipient_key::commands::create([1; 32])
            .expect("recipient")
            .value;
        let input = CreateKeyWrap {
            workspace_id: [1; 32],
            created_at_ms: 10,
            signer_endpoint_shared_id: [3; 32],
            signer_private_key: [9; 32],
            removal_frontier_id: [2; 32],
            wrapped_secret_kind: WrappedSecretKind::FrontierRoot,
            wrapped_secret_id: local_secret.local_key_secret_id,
            wrapped_source_secret_id: [0; 32],
            wrapped_tombstone_node_id: [0; 32],
            range_start: 0,
            range_width: 0,
            bit_depth: 0,
            event_id_prefix: [0; 32],
            key_secret: local_secret.event.key_secret,
            recipient_key_id: [4; 32],
            recipient_key: recipient.recipient_key,
        };

        let first = create(input.clone()).expect("first");
        let second = create(input).expect("second");

        assert_eq!(first.value.key_wrap_id, second.value.key_wrap_id);
        assert_eq!(
            first.events[0].record().canonical_bytes,
            second.events[0].record().canonical_bytes
        );
    }
}
