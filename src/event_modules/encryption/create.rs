//! Local constructors for target encryption facts.

use crate::core::crypto;
use crate::core::facts::Fact;
use crate::event_modules::signed_fact;

use super::fact::{
    KeyWrapFact, LocalHistoryNodeSecretFact, LocalKeySecretFact, RecipientKeyFact,
    WrappedSecretKind, KEY_WRAP_CIPHERTEXT_BYTES,
};
use super::intent::MaterializeKeyWrapsIntent;
use super::{context, layout};

pub const KEY_WRAP_PURPOSE: &[u8] = b"topo key wrap v1";
const KEY_WRAP_CREATED_AT_MS: u64 = 0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WrapMaterial {
    signer_endpoint_id: [u8; 32],
    secret: crypto::XChaCha20Poly1305Key,
    wrapped_secret_kind: WrappedSecretKind,
    wrapped_secret_id: [u8; 32],
    wrapped_source_secret_id: [u8; 32],
    wrapped_tombstone_node_id: [u8; 32],
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    event_id_prefix: [u8; 32],
}

pub fn materialize_key_wrap_fact(
    intent: &MaterializeKeyWrapsIntent,
    recipient_fact: &Fact,
    source_fact: &Fact,
) -> Result<Fact, String> {
    let recipient = layout::decode_recipient_key(&recipient_fact.bytes)?;
    if recipient_fact.id != intent.recipient_key_id {
        return Err("recipient fact id does not match materialize intent".to_string());
    }
    if recipient.workspace_id != intent.workspace_id {
        return Err("recipient key workspace does not match materialize intent".to_string());
    }
    if recipient.recipient_key.iter().all(|byte| *byte == 0) {
        return Err("recipient key material cannot be empty".to_string());
    }

    let material = wrap_material(intent, source_fact)?;
    let sender_wrap_secret = deterministic_sender_wrap_secret(intent, &recipient, &material);
    let sender_wrap_public_key = crypto::x25519_public_key(&sender_wrap_secret);
    let nonce = deterministic_nonce(intent, &recipient, &material);
    let mut wrap = KeyWrapFact {
        workspace_id: intent.workspace_id,
        created_at_ms: KEY_WRAP_CREATED_AT_MS,
        signer_endpoint_id: material.signer_endpoint_id,
        frontier_id: intent.frontier_id,
        wrapped_secret_kind: material.wrapped_secret_kind,
        wrapped_secret_id: material.wrapped_secret_id,
        wrapped_source_secret_id: material.wrapped_source_secret_id,
        wrapped_tombstone_node_id: material.wrapped_tombstone_node_id,
        range_start: material.range_start,
        range_width: material.range_width,
        bit_depth: material.bit_depth,
        event_id_prefix: material.event_id_prefix,
        recipient_key_id: intent.recipient_key_id,
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
        context::workspace_scope(intent.workspace_id),
        KEY_WRAP_CREATED_AT_MS,
        layout::encode_key_wrap(&wrap)?,
    ))
}

pub fn materialize_signed_key_wrap_fact(
    intent: &MaterializeKeyWrapsIntent,
    recipient_fact: &Fact,
    source_fact: &Fact,
    signer_secret_fact: &Fact,
) -> Result<Fact, String> {
    let wrap = materialize_key_wrap_fact(intent, recipient_fact, source_fact)?;
    let signer = signed_fact::layout::decode_local_signer_secret(&signer_secret_fact.bytes)?;
    if signer_secret_fact.id != intent.signer_secret_fact_id {
        return Err("signer secret fact id does not match materialize intent".to_string());
    }
    let key_wrap = layout::decode_key_wrap(&wrap.bytes)?;
    if signer.signer_id != key_wrap.signer_endpoint_id {
        return Err("signer secret does not match key wrap signer".to_string());
    }
    let signed_bytes =
        signed_fact::create::sign_payload_bytes(signer.signer_id, &signer.private_key, wrap.bytes)?;
    Ok(Fact::new(wrap.scope, wrap.timestamp, signed_bytes))
}

fn wrap_material(
    intent: &MaterializeKeyWrapsIntent,
    source_fact: &Fact,
) -> Result<WrapMaterial, String> {
    if source_fact.id != intent.source_fact_id {
        return Err("source fact id does not match materialize intent".to_string());
    }
    match intent.source {
        context::WrapSourceKind::FrontierRoot => {
            let source = layout::decode_local_key_secret(&source_fact.bytes)?;
            require_source_workspace_and_frontier(intent, source.workspace_id, source.frontier_id)?;
            Ok(root_material(source_fact.id, source))
        }
        context::WrapSourceKind::HistoryNode {
            range_start,
            range_width,
            bit_depth,
            event_id_prefix,
        } => {
            let source = layout::decode_local_history_node_secret(&source_fact.bytes)?;
            require_source_workspace_and_frontier(intent, source.workspace_id, source.frontier_id)?;
            if source.range_start != range_start
                || source.range_width != range_width
                || source.bit_depth != bit_depth
                || source.event_id_prefix != event_id_prefix
            {
                return Err(
                    "history source coordinate does not match materialize intent".to_string(),
                );
            }
            Ok(history_material(source_fact.id, source))
        }
    }
}

fn root_material(source_id: [u8; 32], source: LocalKeySecretFact) -> WrapMaterial {
    WrapMaterial {
        signer_endpoint_id: source.owner_endpoint_id,
        secret: source.key_secret,
        wrapped_secret_kind: WrappedSecretKind::FrontierRoot,
        wrapped_secret_id: source_id,
        wrapped_source_secret_id: [0; 32],
        wrapped_tombstone_node_id: [0; 32],
        range_start: 0,
        range_width: 0,
        bit_depth: 0,
        event_id_prefix: [0; 32],
    }
}

fn history_material(source_id: [u8; 32], source: LocalHistoryNodeSecretFact) -> WrapMaterial {
    WrapMaterial {
        signer_endpoint_id: source.owner_endpoint_id,
        secret: source.node_secret,
        wrapped_secret_kind: WrappedSecretKind::HistoryNode,
        wrapped_secret_id: source_id,
        wrapped_source_secret_id: source.source_secret_id,
        wrapped_tombstone_node_id: source.tombstone_node_id,
        range_start: source.range_start,
        range_width: source.range_width,
        bit_depth: source.bit_depth,
        event_id_prefix: source.event_id_prefix,
    }
}

fn require_source_workspace_and_frontier(
    intent: &MaterializeKeyWrapsIntent,
    workspace_id: [u8; 32],
    frontier_id: [u8; 32],
) -> Result<(), String> {
    if workspace_id != intent.workspace_id {
        return Err("source workspace does not match materialize intent".to_string());
    }
    if frontier_id != intent.frontier_id {
        return Err("source frontier does not match materialize intent".to_string());
    }
    Ok(())
}

fn deterministic_sender_wrap_secret(
    intent: &MaterializeKeyWrapsIntent,
    recipient: &RecipientKeyFact,
    material: &WrapMaterial,
) -> crypto::X25519PrivateKey {
    crypto::blake3_keyed_hash(
        &material.secret,
        b"topo key wrap sender x25519 v1",
        &deterministic_wrap_info(intent, recipient, material),
    )
}

fn deterministic_nonce(
    intent: &MaterializeKeyWrapsIntent,
    recipient: &RecipientKeyFact,
    material: &WrapMaterial,
) -> crypto::XChaCha20Poly1305Nonce {
    let full = crypto::blake3_keyed_hash(
        &material.secret,
        b"topo key wrap nonce v1",
        &deterministic_wrap_info(intent, recipient, material),
    );
    full[..crypto::XCHACHA20_POLY1305_NONCE_BYTES]
        .try_into()
        .expect("nonce slice has fixed length")
}

fn deterministic_wrap_info(
    intent: &MaterializeKeyWrapsIntent,
    recipient: &RecipientKeyFact,
    material: &WrapMaterial,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 * 8 + 1 + 8 + 8 + 2);
    out.extend_from_slice(&intent.workspace_id);
    out.extend_from_slice(&material.signer_endpoint_id);
    out.extend_from_slice(&intent.frontier_id);
    out.push(material.wrapped_secret_kind.as_u8());
    out.extend_from_slice(&material.wrapped_secret_id);
    out.extend_from_slice(&material.wrapped_source_secret_id);
    out.extend_from_slice(&material.wrapped_tombstone_node_id);
    out.extend_from_slice(&material.range_start.to_be_bytes());
    out.extend_from_slice(&material.range_width.to_be_bytes());
    out.extend_from_slice(&material.bit_depth.to_be_bytes());
    out.extend_from_slice(&material.event_id_prefix);
    out.extend_from_slice(&intent.recipient_key_id);
    out.extend_from_slice(&recipient.recipient_key);
    out
}

fn associated_data(wrap: &KeyWrapFact) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + (32 * 9) + 1 + 8 + 8 + 2);
    out.push(layout::TYPE_KEY_WRAP);
    out.extend_from_slice(&wrap.workspace_id);
    out.extend_from_slice(&wrap.frontier_id);
    out.push(wrap.wrapped_secret_kind.as_u8());
    out.extend_from_slice(&wrap.wrapped_secret_id);
    out.extend_from_slice(&wrap.wrapped_source_secret_id);
    out.extend_from_slice(&wrap.wrapped_tombstone_node_id);
    out.extend_from_slice(&wrap.range_start.to_be_bytes());
    out.extend_from_slice(&wrap.range_width.to_be_bytes());
    out.extend_from_slice(&wrap.bit_depth.to_be_bytes());
    out.extend_from_slice(&wrap.event_id_prefix);
    out.extend_from_slice(&wrap.recipient_key_id);
    out.extend_from_slice(&wrap.sender_wrap_public_key);
    out.extend_from_slice(&wrap.signer_endpoint_id);
    out
}
