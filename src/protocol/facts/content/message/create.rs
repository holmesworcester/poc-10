//! `send_message` semantic content-message authoring.
//!
//! Message facts keep their semantic content-message type. The user-visible
//! text is the encrypted field inside that fact, and projection opens it only
//! when matching key context is available.

use crate::core::command_context::{CommandContext, CommandOutput, WorkspaceId};
use crate::core::crypto::{self, XChaCha20Poly1305Nonce, XCHACHA20_POLY1305_TAG_BYTES};
use crate::core::facts::{Fact, FactScope, ScopeKind};
use crate::core::wire;
use crate::protocol::facts::content::message::fact::{
    ContentMessageFact, CIPHERTEXT_BYTES, NONCE_BYTES, UNIX_MINUTE_MS,
};
use crate::protocol::facts::content::message::layout;
use crate::protocol::facts::content::message::rows;
use crate::protocol::facts::encryption;
use crate::protocol::facts::identity;
use crate::protocol::facts::identity::signed_fact::{self, create as signed_fact_create};

pub const TEXT_LENGTH_PREFIX_BYTES: usize = 4;
pub const PLAINTEXT_SLOT_BYTES: usize = CIPHERTEXT_BYTES - XCHACHA20_POLY1305_TAG_BYTES;
pub const MAX_TEXT_BYTES: usize = PLAINTEXT_SLOT_BYTES - TEXT_LENGTH_PREFIX_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendReceipt {
    pub workspace_id: WorkspaceId,
    pub message_fact_id: crate::core::facts::FactId,
    pub created_at_ms: u64,
}

pub fn send_message(
    ctx: &CommandContext<'_>,
    workspace_id: WorkspaceId,
    text: &str,
) -> Result<CommandOutput<SendReceipt>, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("send_message text must not be blank".to_string());
    }
    if text.as_bytes().len() > MAX_TEXT_BYTES {
        return Err(format!(
            "send_message text exceeds {MAX_TEXT_BYTES} byte encrypted slot"
        ));
    }

    let signing = ctx.local_signing_capability(workspace_id)?;
    let encryption = ctx.local_encryption_capability(workspace_id)?;
    if signing.fact.workspace_id != workspace_id {
        return Err("signing capability is not bound to this workspace".to_string());
    }
    if encryption.fact.workspace_id != workspace_id {
        return Err("encryption capability is not bound to this workspace".to_string());
    }

    let created_at_ms = ctx.next_timestamp();
    let minute = created_at_ms / UNIX_MINUTE_MS;
    let active_setting = encryption::disappearing_messages_setting::queries::active_for_workspace(
        ctx.store(),
        workspace_id,
    )?;
    if let Some(setting) = &active_setting {
        if minute < setting.retire_minute {
            return Err("send_message minute is below the active disappearing floor".to_string());
        }
    }
    if minute < retained_floor_from_tombstones(ctx, workspace_id)? {
        return Err("no retained ancestor covers message minute".to_string());
    }
    let expires_at_minute = active_setting
        .as_ref()
        .map(|setting| minute.saturating_add(u64::from(setting.ttl_minutes)))
        .unwrap_or(u64::MAX);
    let disappearing_setting_id = active_setting
        .as_ref()
        .map(|setting| setting.setting_id)
        .unwrap_or([0; 32]);

    let nonce = deterministic_nonce(workspace_id, signing.fact.signer_id, created_at_ms);
    let plaintext = pad_plaintext(text.as_bytes())?;
    let ciphertext = crypto::xchacha20poly1305_encrypt(
        &encryption.fact.key_secret,
        &associated_data(workspace_id, encryption.fact.frontier_id, minute),
        &nonce,
        &plaintext,
    )?;
    if ciphertext.len() != CIPHERTEXT_BYTES {
        return Err(format!(
            "content message ciphertext is {} bytes, expected {CIPHERTEXT_BYTES}",
            ciphertext.len()
        ));
    }

    let author_user_id = local_author_user_id(ctx, workspace_id)?.unwrap_or(signing.fact.signer_id);
    let message = ContentMessageFact {
        workspace_id,
        created_at_ms,
        author_user_id,
        signer_id: signing.fact.signer_id,
        frontier_id: encryption.fact.frontier_id,
        local_history_node_secret_id: [0; 32],
        expires_at_minute,
        disappearing_setting_id,
        minute,
        leaf_id: [0; 32],
        nonce,
        ciphertext,
    };
    let payload = layout::encode_fact(&message)?;
    let envelope_bytes = signed_fact_create::sign_payload_bytes(
        signing.fact.signer_id,
        &signing.fact.private_key,
        payload,
    )?;
    debug_assert_eq!(envelope_bytes.len(), signed_fact::SIGNED_FACT_BYTES);

    let fact = Fact::new(
        FactScope::Scoped {
            kind: ScopeKind::new("workspace").expect("valid workspace scope"),
            id: workspace_id,
        },
        created_at_ms,
        envelope_bytes,
    );

    Ok(CommandOutput::new(SendReceipt {
        workspace_id,
        message_fact_id: fact.id,
        created_at_ms,
    })
    .with_facts(vec![fact]))
}

fn local_author_user_id(
    ctx: &CommandContext<'_>,
    workspace_id: WorkspaceId,
) -> Result<Option<crate::core::facts::FactId>, String> {
    Ok(
        identity::workspace::local_membership::local_membership(ctx.store(), workspace_id)?
            .map(|membership| membership.user_authority_fact_id),
    )
}

fn retained_floor_from_tombstones(
    ctx: &CommandContext<'_>,
    workspace_id: WorkspaceId,
) -> Result<u64, String> {
    let tombstones = ctx
        .store()
        .table_rows_with_key_prefix(rows::MESSAGE_TOMBSTONE_ROWS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load message tombstones for send: {err}"))?;
    tombstones
        .into_iter()
        .map(|(key, value)| rows::decode_message_tombstone_row(&key, &value))
        .try_fold(0, |floor, row| {
            row.map(|row| floor.max(row.authored_minute.saturating_add(1)))
        })
}

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

pub fn associated_data(
    workspace_id: WorkspaceId,
    frontier_id: crate::core::facts::FactId,
    minute: u64,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 + 32 + 8);
    bytes.extend_from_slice(&workspace_id);
    bytes.extend_from_slice(&frontier_id);
    let mut minute_bytes = [0u8; 8];
    wire::put_u64be(minute, &mut minute_bytes).expect("eight-byte minute slot");
    bytes.extend_from_slice(&minute_bytes);
    bytes
}

pub fn deterministic_nonce(
    workspace_id: WorkspaceId,
    signer_id: crate::core::facts::FactId,
    created_at_ms: u64,
) -> XChaCha20Poly1305Nonce {
    let mut info = Vec::with_capacity(32 + 32 + 8);
    info.extend_from_slice(&workspace_id);
    info.extend_from_slice(&signer_id);
    let mut ts = [0u8; 8];
    wire::put_u64be(created_at_ms, &mut ts).expect("eight-byte timestamp slot");
    info.extend_from_slice(&ts);
    let hash = crypto::hash(&info);
    let mut nonce = [0u8; NONCE_BYTES];
    nonce.copy_from_slice(&hash[..NONCE_BYTES]);
    nonce
}
