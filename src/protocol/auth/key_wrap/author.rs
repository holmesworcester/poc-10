//! Pure constructors and validators for derived key-wrap facts.
//!
//! Projection uses this module when context has already supplied the exact
//! facts needed to create or admit a key wrap, unwrap a key wrap into local
//! secret material, or validate derived local material.

use crate::core::crypto;
use crate::core::facts::{Fact, FactId, FactScope};

use crate::protocol::auth::key_wrap_creation::fact::KeyWrapCreationFact;
use crate::protocol::auth::key_wrap_recovery::fact::KeyWrapRecoveryFact;
use crate::protocol::auth::local_history_node_secret::fact::LocalHistoryNodeSecretFact;
use crate::protocol::auth::local_key_secret::fact::LocalKeySecretFact;
use crate::protocol::auth::local_recipient_key::fact::LocalRecipientKeyFact;
use crate::protocol::auth::local_recipient_key::project::decode as local_recipient_layout;
use crate::protocol::auth::local_signer_secret::project::decode as local_signer_secret_layout;
use crate::protocol::auth::recipient_key::fact::RecipientKeyFact;
use crate::protocol::auth::recipient_key::project::decode as recipient_key_layout;
use crate::protocol::auth::removal_frontier::project::decode as removal_frontier_decode;

use super::fact::{KeyWrapFact, WrapSourceKind, WrappedSecretKind, KEY_WRAP_CIPHERTEXT_BYTES};
use super::{encode, project::decode};
use crate::protocol::auth::local_history_node_secret::encode as local_history_layout_encode;
use crate::protocol::auth::local_history_node_secret::project::decode as local_history_layout_decode;
use crate::protocol::auth::local_key_secret::encode as local_key_secret_layout_encode;
use crate::protocol::auth::local_key_secret::project::decode as local_key_secret_layout_decode;

pub const KEY_WRAP_PURPOSE: &[u8] = b"topo key wrap v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WrapMaterial {
    signer_endpoint_id: [u8; 32],
    created_at_ms: u64,
    secret: crypto::XChaCha20Poly1305Key,
    wrapped_secret_kind: WrappedSecretKind,
    wrapped_secret_id: [u8; 32],
    wrapped_source_secret_id: [u8; 32],
    wrapped_tombstone_node_id: [u8; 32],
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    fact_id_prefix: [u8; 32],
}

pub fn create_key_wrap_fact(
    creation: &KeyWrapCreationFact,
    recipient_fact_id: FactId,
    recipient_fact_bytes: &[u8],
    source_fact_id: FactId,
    source_fact_received_at: u64,
    source_fact_bytes: &[u8],
) -> Result<Fact, String> {
    let recipient = recipient_key_layout::decode_recipient_key(recipient_fact_bytes)?;
    if recipient_fact_id != creation.recipient_key_id {
        return Err("recipient fact id does not match key_wrap_creation fact".to_string());
    }
    if recipient.workspace_id != creation.workspace_id {
        return Err("recipient key workspace does not match key_wrap_creation fact".to_string());
    }
    if recipient.recipient_key.iter().all(|byte| *byte == 0) {
        return Err("recipient key material cannot be empty".to_string());
    }

    let material = wrap_material(
        creation,
        source_fact_id,
        source_fact_received_at,
        source_fact_bytes,
    )?;
    let sender_wrap_secret = deterministic_sender_wrap_secret(creation, &recipient, &material);
    let sender_wrap_public_key = crypto::x25519_public_key(&sender_wrap_secret);
    let nonce = deterministic_nonce(creation, &recipient, &material);
    let mut wrap = KeyWrapFact {
        workspace_id: creation.workspace_id,
        created_at_ms: material.created_at_ms,
        signer_endpoint_id: material.signer_endpoint_id,
        frontier_id: creation.frontier_id,
        wrapped_secret_kind: material.wrapped_secret_kind,
        wrapped_secret_id: material.wrapped_secret_id,
        wrapped_source_secret_id: material.wrapped_source_secret_id,
        wrapped_tombstone_node_id: material.wrapped_tombstone_node_id,
        range_start: material.range_start,
        range_width: material.range_width,
        bit_depth: material.bit_depth,
        fact_id_prefix: material.fact_id_prefix,
        recipient_key_id: creation.recipient_key_id,
        sender_wrap_public_key,
        nonce,
        ciphertext: [0; KEY_WRAP_CIPHERTEXT_BYTES],
    };
    let ciphertext = crypto::x25519_xchacha20poly1305_encrypt(
        &sender_wrap_secret,
        &recipient.recipient_key,
        KEY_WRAP_PURPOSE,
        &associated_data(&wrap),
        &wrap.nonce,
        &material.secret,
    )?;
    wrap.ciphertext = ciphertext
        .try_into()
        .map_err(|_| "key wrap ciphertext length mismatch".to_string())?;

    Ok(Fact::new(
        crate::protocol::auth::workspace::scope(creation.workspace_id),
        wrap.created_at_ms,
        encode::encode_key_wrap(&wrap)?,
    ))
}

pub fn unwrap_key_wrap_fact(
    recovery: &KeyWrapRecoveryFact,
    key_wrap_fact_id: FactId,
    key_wrap_fact_bytes: &[u8],
    local_recipient_key_fact_id: FactId,
    local_recipient_key_fact_bytes: &[u8],
    recipient_fact_id: FactId,
    recipient_fact_bytes: &[u8],
    frontier_fact_id: FactId,
    frontier_fact_bytes: &[u8],
) -> Result<Fact, String> {
    if key_wrap_fact_id != recovery.key_wrap_id {
        return Err("key wrap fact id does not match key_wrap_recovery fact".to_string());
    }
    if local_recipient_key_fact_id != recovery.local_recipient_key_id {
        return Err(
            "local recipient key fact id does not match key_wrap_recovery fact".to_string(),
        );
    }
    if recipient_fact_id != recovery.recipient_key_id {
        return Err("recipient fact id does not match key_wrap_recovery fact".to_string());
    }
    if frontier_fact_id != recovery.frontier_id {
        return Err("frontier fact id does not match key_wrap_recovery fact".to_string());
    }

    let wrap = decode::decode_key_wrap(key_wrap_fact_bytes)?;
    require_unwrap_coordinate(recovery, &wrap)?;

    let recipient = recipient_key_layout::decode_recipient_key(recipient_fact_bytes)?;
    if recipient.workspace_id != recovery.workspace_id {
        return Err("recipient key workspace does not match key_wrap_recovery fact".to_string());
    }
    let frontier = removal_frontier_decode::decode_removal_frontier(frontier_fact_bytes)?;
    if frontier.workspace_id != recovery.workspace_id {
        return Err("removal frontier workspace does not match key_wrap_recovery fact".to_string());
    }
    if frontier.owner_endpoint_id != wrap.signer_endpoint_id {
        return Err("key wrap signer does not own unwrap frontier".to_string());
    }
    let local = local_recipient_layout::decode_local_recipient_key(local_recipient_key_fact_bytes)?;
    require_local_recipient_key(recovery, &recipient, &local)?;

    let plaintext = crypto::x25519_xchacha20poly1305_decrypt(
        &local.recipient_secret,
        &wrap.sender_wrap_public_key,
        KEY_WRAP_PURPOSE,
        &associated_data(&wrap),
        &wrap.nonce,
        &wrap.ciphertext,
    )?;
    let secret = plaintext
        .try_into()
        .map_err(|_| "key wrap plaintext length mismatch".to_string())?;

    let unwrapped = match wrap.wrapped_secret_kind {
        WrappedSecretKind::FrontierRoot => root_secret_fact(&wrap, secret)?,
        WrappedSecretKind::HistoryNode => history_secret_fact(&wrap, secret)?,
    };
    if unwrapped.id != wrap.wrapped_secret_id {
        return Err("unwrapped secret fact id does not match key wrap target".to_string());
    }
    Ok(unwrapped)
}

pub fn create_validated_key_wrap_facts(
    creation: &KeyWrapCreationFact,
    recipient_fact_id: FactId,
    recipient_fact_bytes: &[u8],
    source_fact_id: FactId,
    source_fact_received_at: u64,
    source_fact_bytes: &[u8],
    signer_secret_fact_id: FactId,
    signer_secret_fact_bytes: &[u8],
) -> Result<[Fact; 2], String> {
    let wrap = create_key_wrap_fact(
        creation,
        recipient_fact_id,
        recipient_fact_bytes,
        source_fact_id,
        source_fact_received_at,
        source_fact_bytes,
    )?;
    let signer = local_signer_secret_layout::decode_fact(signer_secret_fact_bytes)?;
    if signer_secret_fact_id != creation.signer_secret_fact_id {
        return Err("signer secret fact id does not match key_wrap_creation fact".to_string());
    }
    if signer.workspace_id != creation.workspace_id {
        return Err("signer secret workspace does not match key_wrap_creation fact".to_string());
    }
    let key_wrap = decode::decode_key_wrap(&wrap.bytes)?;
    if signer.signer_id != key_wrap.signer_endpoint_id {
        return Err("signer secret does not match key wrap signer".to_string());
    }
    let signature = crate::protocol::auth::signature::author::sign_fact(
        creation.workspace_id,
        &wrap,
        &signer.private_key,
        wrap.timestamp,
    )?;
    Ok([wrap, signature])
}

pub fn admit_key_wrap_fact(bytes: Vec<u8>) -> Result<Fact, String> {
    let wrap = decode::decode_key_wrap(&bytes)?;
    Ok(Fact::new(
        crate::protocol::auth::workspace::scope(wrap.workspace_id),
        wrap.created_at_ms,
        bytes,
    ))
}

fn wrap_material(
    creation: &KeyWrapCreationFact,
    source_fact_id: FactId,
    source_fact_received_at: u64,
    source_fact_bytes: &[u8],
) -> Result<WrapMaterial, String> {
    if source_fact_id != creation.source_fact_id {
        return Err("source fact id does not match key_wrap_creation fact".to_string());
    }
    match creation.source {
        WrapSourceKind::FrontierRoot => {
            let source =
                local_key_secret_layout_decode::decode_local_key_secret(source_fact_bytes)?;
            require_source_workspace_and_frontier(
                creation,
                source.workspace_id,
                source.frontier_id,
            )?;
            if source.owner_endpoint_id != creation.owner_endpoint_id {
                return Err("root source owner does not match key_wrap_creation fact".to_string());
            }
            if source.created_at_ms != creation.frontier_created_at_ms {
                return Err(
                    "root source timestamp does not match key_wrap_creation fact".to_string(),
                );
            }
            Ok(root_material(source_fact_id, source))
        }
        WrapSourceKind::HistoryNode {
            range_start,
            range_width,
            bit_depth,
            fact_id_prefix,
        } => {
            let source =
                local_history_layout_decode::decode_local_history_node_secret(source_fact_bytes)?;
            require_source_workspace_and_frontier(
                creation,
                source.workspace_id,
                source.frontier_id,
            )?;
            if source.owner_endpoint_id != creation.owner_endpoint_id {
                return Err(
                    "history source owner does not match key_wrap_creation fact".to_string()
                );
            }
            if source.range_start != range_start
                || source.range_width != range_width
                || source.bit_depth != bit_depth
                || source.fact_id_prefix != fact_id_prefix
            {
                return Err(
                    "history source coordinate does not match key_wrap_creation fact".to_string(),
                );
            }
            Ok(history_material(
                source_fact_id,
                source_fact_received_at,
                source,
            ))
        }
    }
}

fn root_material(source_id: [u8; 32], source: LocalKeySecretFact) -> WrapMaterial {
    WrapMaterial {
        signer_endpoint_id: source.owner_endpoint_id,
        created_at_ms: source.created_at_ms,
        secret: source.key_secret,
        wrapped_secret_kind: WrappedSecretKind::FrontierRoot,
        wrapped_secret_id: source_id,
        wrapped_source_secret_id: [0; 32],
        wrapped_tombstone_node_id: [0; 32],
        range_start: 0,
        range_width: 0,
        bit_depth: 0,
        fact_id_prefix: [0; 32],
    }
}

fn history_material(
    source_id: [u8; 32],
    source_created_at_ms: u64,
    source: LocalHistoryNodeSecretFact,
) -> WrapMaterial {
    WrapMaterial {
        signer_endpoint_id: source.owner_endpoint_id,
        created_at_ms: source_created_at_ms,
        secret: source.node_secret,
        wrapped_secret_kind: WrappedSecretKind::HistoryNode,
        wrapped_secret_id: source_id,
        wrapped_source_secret_id: source.source_secret_id,
        wrapped_tombstone_node_id: source.tombstone_node_id,
        range_start: source.range_start,
        range_width: source.range_width,
        bit_depth: source.bit_depth,
        fact_id_prefix: source.fact_id_prefix,
    }
}

fn require_unwrap_coordinate(
    recovery: &KeyWrapRecoveryFact,
    wrap: &KeyWrapFact,
) -> Result<(), String> {
    if wrap.workspace_id != recovery.workspace_id {
        return Err("key wrap workspace does not match key_wrap_recovery fact".to_string());
    }
    if wrap.frontier_id != recovery.frontier_id {
        return Err("key wrap frontier does not match key_wrap_recovery fact".to_string());
    }
    if wrap.recipient_key_id != recovery.recipient_key_id {
        return Err("key wrap recipient does not match key_wrap_recovery fact".to_string());
    }
    Ok(())
}

fn require_local_recipient_key(
    recovery: &KeyWrapRecoveryFact,
    recipient: &RecipientKeyFact,
    local: &LocalRecipientKeyFact,
) -> Result<(), String> {
    if local.workspace_id != recovery.workspace_id {
        return Err(
            "local recipient key workspace does not match key_wrap_recovery fact".to_string(),
        );
    }
    if local.recipient_key_id != recovery.recipient_key_id {
        return Err("local recipient key id does not match key_wrap_recovery fact".to_string());
    }
    if local.recipient_key != recipient.recipient_key {
        return Err("local recipient key public key does not match recipient".to_string());
    }
    Ok(())
}

fn root_secret_fact(
    wrap: &KeyWrapFact,
    key_secret: crypto::XChaCha20Poly1305Key,
) -> Result<Fact, String> {
    Ok(Fact::new(
        FactScope::Local,
        wrap.created_at_ms,
        local_key_secret_layout_encode::encode_local_key_secret(&LocalKeySecretFact {
            workspace_id: wrap.workspace_id,
            frontier_id: wrap.frontier_id,
            owner_endpoint_id: wrap.signer_endpoint_id,
            created_at_ms: wrap.created_at_ms,
            key_secret,
        })?,
    ))
}

fn history_secret_fact(
    wrap: &KeyWrapFact,
    node_secret: crypto::XChaCha20Poly1305Key,
) -> Result<Fact, String> {
    Ok(Fact::new(
        FactScope::Local,
        wrap.created_at_ms,
        local_history_layout_encode::encode_local_history_node_secret(
            &LocalHistoryNodeSecretFact {
                workspace_id: wrap.workspace_id,
                frontier_id: wrap.frontier_id,
                owner_endpoint_id: wrap.signer_endpoint_id,
                source_secret_id: wrap.wrapped_source_secret_id,
                range_start: wrap.range_start,
                range_width: wrap.range_width,
                bit_depth: wrap.bit_depth,
                fact_id_prefix: wrap.fact_id_prefix,
                tombstone_node_id: wrap.wrapped_tombstone_node_id,
                node_secret,
            },
        )?,
    ))
}

fn require_source_workspace_and_frontier(
    creation: &KeyWrapCreationFact,
    workspace_id: [u8; 32],
    frontier_id: [u8; 32],
) -> Result<(), String> {
    if workspace_id != creation.workspace_id {
        return Err("source workspace does not match key_wrap_creation fact".to_string());
    }
    if frontier_id != creation.frontier_id {
        return Err("source frontier does not match key_wrap_creation fact".to_string());
    }
    Ok(())
}

fn deterministic_sender_wrap_secret(
    creation: &KeyWrapCreationFact,
    recipient: &RecipientKeyFact,
    material: &WrapMaterial,
) -> crypto::X25519PrivateKey {
    crypto::blake3_keyed_hash(
        &material.secret,
        b"topo key wrap sender x25519 v1",
        &deterministic_wrap_info(creation, recipient, material),
    )
}

fn deterministic_nonce(
    creation: &KeyWrapCreationFact,
    recipient: &RecipientKeyFact,
    material: &WrapMaterial,
) -> crypto::XChaCha20Poly1305Nonce {
    let full = crypto::blake3_keyed_hash(
        &material.secret,
        b"topo key wrap nonce v1",
        &deterministic_wrap_info(creation, recipient, material),
    );
    full[..crypto::XCHACHA20_POLY1305_NONCE_BYTES]
        .try_into()
        .expect("nonce slice has fixed length")
}

fn deterministic_wrap_info(
    creation: &KeyWrapCreationFact,
    recipient: &RecipientKeyFact,
    material: &WrapMaterial,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 * 8 + 1 + 8 + 8 + 2);
    out.extend_from_slice(&creation.workspace_id);
    out.extend_from_slice(&material.signer_endpoint_id);
    out.extend_from_slice(&creation.frontier_id);
    out.push(material.wrapped_secret_kind.as_u8());
    out.extend_from_slice(&material.wrapped_secret_id);
    out.extend_from_slice(&material.wrapped_source_secret_id);
    out.extend_from_slice(&material.wrapped_tombstone_node_id);
    out.extend_from_slice(&material.range_start.to_be_bytes());
    out.extend_from_slice(&material.range_width.to_be_bytes());
    out.extend_from_slice(&material.bit_depth.to_be_bytes());
    out.extend_from_slice(&material.fact_id_prefix);
    out.extend_from_slice(&creation.recipient_key_id);
    out.extend_from_slice(&recipient.recipient_key);
    out
}

fn associated_data(wrap: &KeyWrapFact) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + (32 * 9) + 1 + 8 + 8 + 2);
    out.push(encode::TYPE_KEY_WRAP);
    out.extend_from_slice(&wrap.workspace_id);
    out.extend_from_slice(&wrap.frontier_id);
    out.push(wrap.wrapped_secret_kind.as_u8());
    out.extend_from_slice(&wrap.wrapped_secret_id);
    out.extend_from_slice(&wrap.wrapped_source_secret_id);
    out.extend_from_slice(&wrap.wrapped_tombstone_node_id);
    out.extend_from_slice(&wrap.range_start.to_be_bytes());
    out.extend_from_slice(&wrap.range_width.to_be_bytes());
    out.extend_from_slice(&wrap.bit_depth.to_be_bytes());
    out.extend_from_slice(&wrap.fact_id_prefix);
    out.extend_from_slice(&wrap.recipient_key_id);
    out.extend_from_slice(&wrap.sender_wrap_public_key);
    out.extend_from_slice(&wrap.signer_endpoint_id);
    out
}

// Tests.
// Ordered most-central-first: admitting a valid key wrap, then the non-wrap rejection guard.
#[cfg(test)]
mod tests {
    use super::*;

    fn key_wrap_bytes() -> (Vec<u8>, KeyWrapFact) {
        let signer_id = [2; 32];
        let wrap = KeyWrapFact {
            workspace_id: [1; 32],
            created_at_ms: 1_700_000_321,
            signer_endpoint_id: signer_id,
            frontier_id: [3; 32],
            wrapped_secret_kind: WrappedSecretKind::FrontierRoot,
            wrapped_secret_id: [4; 32],
            wrapped_source_secret_id: [0; 32],
            wrapped_tombstone_node_id: [0; 32],
            range_start: 0,
            range_width: 0,
            bit_depth: 0,
            fact_id_prefix: [0; 32],
            recipient_key_id: [5; 32],
            sender_wrap_public_key: [6; 32],
            nonce: [7; 24],
            ciphertext: [8; KEY_WRAP_CIPHERTEXT_BYTES],
        };
        let bytes = encode::encode_key_wrap(&wrap).expect("encode key wrap");
        (bytes, wrap)
    }

    #[test]
    fn admit_key_wrap_uses_inner_workspace_and_created_at() {
        let (bytes, wrap) = key_wrap_bytes();

        let fact = admit_key_wrap_fact(bytes.clone()).expect("admit key wrap");

        assert_eq!(
            fact.scope,
            crate::protocol::auth::workspace::scope(wrap.workspace_id)
        );
        assert_eq!(fact.timestamp, wrap.created_at_ms);
        assert_eq!(fact.bytes, bytes);
    }

    #[test]
    fn admit_key_wrap_rejects_other_payloads() {
        let bytes =
            vec![crate::protocol::auth::recipient_key::TYPE_RECIPIENT_KEY; encode::KEY_WRAP_BYTES];

        let err = admit_key_wrap_fact(bytes).expect_err("recipient key is not a key wrap");
        assert!(err.contains("key wrap"), "{err}");
    }
}
