//! Local constructors for target encryption facts.

use crate::core::crypto;
use crate::core::facts::{Fact, FactScope};
use crate::event_modules::signed_fact;

use super::fact::{
    KeyWrapFact, LocalHistoryNodeSecretFact, LocalKeySecretFact, LocalRecipientKeyFact,
    RecipientKeyFact, WrappedSecretKind, KEY_WRAP_CIPHERTEXT_BYTES,
};
use super::intent::{
    MaterializeKeyWrapsIntent, PurgeRetiredRecipientMaterialIntent, UnwrapKeyWrapIntent,
};
use super::{context, layout};

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
        created_at_ms: material.created_at_ms,
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
        wrap.created_at_ms,
        layout::encode_key_wrap(&wrap)?,
    ))
}

pub fn unwrap_key_wrap_fact(
    intent: &UnwrapKeyWrapIntent,
    key_wrap_fact: &Fact,
    local_recipient_key_fact: &Fact,
    recipient_fact: &Fact,
) -> Result<Fact, String> {
    if key_wrap_fact.id != intent.key_wrap_id {
        return Err("key wrap fact id does not match unwrap intent".to_string());
    }
    if local_recipient_key_fact.id != intent.local_recipient_key_id {
        return Err("local recipient key fact id does not match unwrap intent".to_string());
    }
    if recipient_fact.id != intent.recipient_key_id {
        return Err("recipient fact id does not match unwrap intent".to_string());
    }

    let envelope = signed_fact::layout::decode_signed_fact(&key_wrap_fact.bytes)?;
    if envelope.inner_type != layout::TYPE_KEY_WRAP {
        return Err("signed fact does not contain an encryption key wrap".to_string());
    }
    let wrap = layout::decode_key_wrap(&envelope.payload)?;
    require_unwrap_coordinate(intent, &wrap)?;

    let recipient = layout::decode_recipient_key(&recipient_fact.bytes)?;
    if recipient.workspace_id != intent.workspace_id {
        return Err("recipient key workspace does not match unwrap intent".to_string());
    }
    let local = layout::decode_local_recipient_key(&local_recipient_key_fact.bytes)?;
    require_local_recipient_key(intent, &recipient, &local)?;

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

pub fn admit_signed_key_wrap_fact(bytes: Vec<u8>) -> Result<Fact, String> {
    let envelope = signed_fact::layout::decode_signed_fact(&bytes)?;
    if envelope.inner_type != layout::TYPE_KEY_WRAP {
        return Err("signed fact does not contain an encryption key wrap".to_string());
    }
    let wrap = layout::decode_key_wrap(&envelope.payload)?;
    if envelope.signer_id != wrap.signer_endpoint_id {
        return Err("key wrap signer does not match signed envelope signer".to_string());
    }
    Ok(Fact::new(
        context::workspace_scope(wrap.workspace_id),
        wrap.created_at_ms,
        bytes,
    ))
}

pub fn validate_retired_recipient_material(
    intent: &PurgeRetiredRecipientMaterialIntent,
    local_recipient_key_fact: &Fact,
) -> Result<(), String> {
    if local_recipient_key_fact.id != intent.local_recipient_key_id {
        return Err("local recipient key fact id does not match purge intent".to_string());
    }
    if local_recipient_key_fact.scope != FactScope::Local {
        return Err("retired recipient material is not local".to_string());
    }
    let local = layout::decode_local_recipient_key(&local_recipient_key_fact.bytes)?;
    if local.workspace_id != intent.workspace_id {
        return Err("retired recipient material workspace mismatch".to_string());
    }
    if local.recipient_key_id != intent.recipient_key_id {
        return Err("retired recipient material recipient mismatch".to_string());
    }
    Ok(())
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
            Ok(history_material(
                source_fact.id,
                source_fact.timestamp,
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
        event_id_prefix: [0; 32],
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
        event_id_prefix: source.event_id_prefix,
    }
}

fn require_unwrap_coordinate(
    intent: &UnwrapKeyWrapIntent,
    wrap: &KeyWrapFact,
) -> Result<(), String> {
    if wrap.workspace_id != intent.workspace_id {
        return Err("key wrap workspace does not match unwrap intent".to_string());
    }
    if wrap.frontier_id != intent.frontier_id {
        return Err("key wrap frontier does not match unwrap intent".to_string());
    }
    if wrap.recipient_key_id != intent.recipient_key_id {
        return Err("key wrap recipient does not match unwrap intent".to_string());
    }
    Ok(())
}

fn require_local_recipient_key(
    intent: &UnwrapKeyWrapIntent,
    recipient: &RecipientKeyFact,
    local: &LocalRecipientKeyFact,
) -> Result<(), String> {
    if local.workspace_id != intent.workspace_id {
        return Err("local recipient key workspace does not match unwrap intent".to_string());
    }
    if local.recipient_key_id != intent.recipient_key_id {
        return Err("local recipient key id does not match unwrap intent".to_string());
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
        crate::core::facts::FactScope::Local,
        wrap.created_at_ms,
        layout::encode_local_key_secret(&LocalKeySecretFact {
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
        crate::core::facts::FactScope::Local,
        wrap.created_at_ms,
        layout::encode_local_history_node_secret(&LocalHistoryNodeSecretFact {
            workspace_id: wrap.workspace_id,
            frontier_id: wrap.frontier_id,
            owner_endpoint_id: wrap.signer_endpoint_id,
            source_secret_id: wrap.wrapped_source_secret_id,
            range_start: wrap.range_start,
            range_width: wrap.range_width,
            bit_depth: wrap.bit_depth,
            event_id_prefix: wrap.event_id_prefix,
            tombstone_node_id: wrap.wrapped_tombstone_node_id,
            node_secret,
        })?,
    ))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn signed_key_wrap_bytes() -> (Vec<u8>, KeyWrapFact) {
        let signer_private_key = [9; 32];
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
            event_id_prefix: [0; 32],
            recipient_key_id: [5; 32],
            sender_wrap_public_key: [6; 32],
            nonce: [7; 24],
            ciphertext: [8; KEY_WRAP_CIPHERTEXT_BYTES],
        };
        let payload = layout::encode_key_wrap(&wrap).expect("encode key wrap");
        let bytes =
            signed_fact::create::sign_payload_bytes(signer_id, &signer_private_key, payload)
                .expect("sign key wrap");
        (bytes, wrap)
    }

    #[test]
    fn admit_signed_key_wrap_uses_inner_workspace_and_created_at() {
        let (bytes, wrap) = signed_key_wrap_bytes();

        let fact = admit_signed_key_wrap_fact(bytes.clone()).expect("admit signed key wrap");

        assert_eq!(fact.scope, context::workspace_scope(wrap.workspace_id));
        assert_eq!(fact.timestamp, wrap.created_at_ms);
        assert_eq!(fact.bytes, bytes);
    }

    #[test]
    fn admit_signed_key_wrap_rejects_other_signed_payloads() {
        let signer_private_key = [9; 32];
        let signer_id = [2; 32];
        let payload = layout::encode_recipient_key(&RecipientKeyFact {
            workspace_id: [1; 32],
            endpoint_id: signer_id,
            recipient_key: [3; 32],
            previous_recipient_key_id: [0; 32],
            created_at_ms: 1_700_000_321,
        })
        .expect("encode recipient key");
        let bytes =
            signed_fact::create::sign_payload_bytes(signer_id, &signer_private_key, payload)
                .expect("sign recipient key");

        let err = admit_signed_key_wrap_fact(bytes).expect_err("recipient key is not a key wrap");
        assert!(err.contains("key wrap"), "{err}");
    }
}
