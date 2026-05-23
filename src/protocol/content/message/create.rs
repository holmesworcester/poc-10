//! `send_message` semantic content-message authoring.
//!
//! Message facts keep their semantic content-message type. The user-visible
//! text is the encrypted field inside that fact, and projection opens it only
//! when matching key context is available.

use crate::core::command_context::{
    CommandContext, CommandOutput, IdentityVault, LocalEncryptionCapability,
    LocalSigningCapability, WorkspaceId,
};
use crate::core::crypto::{self, XChaCha20Poly1305Nonce, XCHACHA20_POLY1305_TAG_BYTES};
use crate::core::facts::{Fact, FactId, FactScope, ScopeKind};
use crate::core::intents::TableDeleteWhere;
use crate::core::intents::Value;
use crate::core::runtime::Runtime;
use crate::core::store::TableName;
use crate::core::wire;
use crate::protocol::auth;
use crate::protocol::auth::signed_envelope::{self, create as signed_envelope_create};
use crate::protocol::content::message::fact::{
    ContentMessageFact, MessageCiphertext, CIPHERTEXT_BYTES, NONCE_BYTES, UNIX_MINUTE_MS,
};
use crate::protocol::content::message::layout;
use crate::protocol::content::message::queries;
use crate::protocol::content::message::rows;
use crate::protocol::content::{disappearing_messages_setting, message};

pub const TEXT_LENGTH_PREFIX_BYTES: usize = 4;
pub const PLAINTEXT_SLOT_BYTES: usize = CIPHERTEXT_BYTES - XCHACHA20_POLY1305_TAG_BYTES;
pub const MAX_TEXT_BYTES: usize = PLAINTEXT_SLOT_BYTES - TEXT_LENGTH_PREFIX_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendReceipt {
    pub workspace_id: WorkspaceId,
    pub message_fact_id: crate::core::facts::FactId,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateReceipt {
    pub workspace_id: WorkspaceId,
    pub generated_facts: usize,
    pub message_text_bytes: usize,
    pub first_timestamp: u64,
    pub last_timestamp: u64,
    pub fact_ids: Vec<FactId>,
}

pub fn send_message(
    ctx: &CommandContext<'_>,
    workspace_id: WorkspaceId,
    text: &str,
) -> Result<CommandOutput<SendReceipt>, String> {
    let created_at_ms = ctx.next_timestamp();
    let fact = build_message_fact(ctx, workspace_id, text, created_at_ms)?;

    Ok(CommandOutput::new(SendReceipt {
        workspace_id,
        message_fact_id: fact.id,
        created_at_ms,
    })
    .with_facts(vec![fact]))
}

pub fn generate_messages(
    ctx: &CommandContext<'_>,
    workspace_id: WorkspaceId,
    count: usize,
    requested_message_text_bytes: usize,
) -> Result<CommandOutput<GenerateReceipt>, String> {
    if count == 0 {
        return Err("generate count must be positive".to_string());
    }
    if requested_message_text_bytes == 0 {
        return Err("generate message text size must be positive".to_string());
    }

    let first_timestamp = ctx.next_timestamp();
    let last_timestamp = first_timestamp
        .checked_add((count - 1) as u64)
        .ok_or_else(|| "generate timestamp range overflows u64".to_string())?;
    let message_text_bytes = requested_message_text_bytes.min(MAX_TEXT_BYTES);

    let mut facts = Vec::with_capacity(count);
    let mut fact_ids = Vec::with_capacity(count);
    for index in 0..count {
        let timestamp = first_timestamp
            .checked_add(index as u64)
            .ok_or_else(|| "generate timestamp overflows u64".to_string())?;
        let text =
            deterministic_generated_text(&workspace_id, timestamp, index, message_text_bytes);
        let fact = build_message_fact(ctx, workspace_id, &text, timestamp)?;
        fact_ids.push(fact.id);
        facts.push(fact);
    }

    Ok(CommandOutput::new(GenerateReceipt {
        workspace_id,
        generated_facts: count,
        message_text_bytes,
        first_timestamp,
        last_timestamp,
        fact_ids,
    })
    .with_facts(facts))
}

fn build_message_fact(
    ctx: &CommandContext<'_>,
    workspace_id: WorkspaceId,
    text: &str,
    created_at_ms: u64,
) -> Result<Fact, String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("send_message text must not be blank".to_string());
    }
    if text.len() > MAX_TEXT_BYTES {
        return Err(format!(
            "send_message text exceeds {MAX_TEXT_BYTES} byte encrypted slot"
        ));
    }

    let signing = ctx.local_signing_capability(workspace_id)?;
    let encryption = ctx.local_encryption_capability(workspace_id)?;
    if signing.workspace_id != workspace_id {
        return Err("signing capability is not bound to this workspace".to_string());
    }
    if encryption.workspace_id != workspace_id {
        return Err("encryption capability is not bound to this workspace".to_string());
    }

    let minute = created_at_ms / UNIX_MINUTE_MS;
    let active_setting =
        disappearing_messages_setting::queries::active_for_workspace(ctx.store(), workspace_id)?;
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

    let nonce = deterministic_nonce(workspace_id, signing.signer_id, created_at_ms);
    let plaintext = pad_plaintext(text.as_bytes())?;
    let ciphertext = crypto::xchacha20poly1305_encrypt(
        &encryption.key_secret,
        &associated_data(workspace_id, encryption.frontier_id, minute),
        &nonce,
        &plaintext,
    )?;
    if ciphertext.len() != CIPHERTEXT_BYTES {
        return Err(format!(
            "content message ciphertext is {} bytes, expected {CIPHERTEXT_BYTES}",
            ciphertext.len()
        ));
    }

    let author_user_id = local_author_user_id(ctx, workspace_id)?.unwrap_or(signing.signer_id);
    let message = ContentMessageFact {
        workspace_id,
        created_at_ms,
        author_user_id,
        signer_id: signing.signer_id,
        frontier_id: encryption.frontier_id,
        local_history_node_secret_id: [0; 32],
        expires_at_minute,
        disappearing_setting_id,
        minute,
        nonce,
        ciphertext: MessageCiphertext::new(&ciphertext)
            .map_err(|err| format!("content message ciphertext: {err}"))?,
    };
    let payload = layout::encode_fact(&message)?;
    let envelope_bytes = signed_envelope_create::sign_payload_bytes(
        signing.signer_id,
        &signing.private_key,
        payload,
    )?;
    debug_assert_eq!(envelope_bytes.len(), signed_envelope::SIGNED_ENVELOPE_BYTES);

    let fact = Fact::new(
        FactScope::Scoped {
            kind: ScopeKind::new("workspace").expect("valid workspace scope"),
            id: workspace_id,
        },
        created_at_ms,
        envelope_bytes,
    );

    Ok(fact)
}

fn deterministic_generated_text(
    workspace_id: &FactId,
    timestamp: u64,
    index: usize,
    size: usize,
) -> String {
    let mut out = Vec::with_capacity(size);
    let mut block = 0u64;
    while out.len() < size {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"topo:poc10:generated-message-text:v1");
        hasher.update(workspace_id);
        hasher.update(&timestamp.to_be_bytes());
        hasher.update(&(index as u64).to_be_bytes());
        hasher.update(&block.to_be_bytes());
        for byte in hasher.finalize().as_bytes() {
            out.push(b'a' + (byte % 26));
            if out.len() == size {
                break;
            }
        }
        block = block.saturating_add(1);
    }
    String::from_utf8(out).expect("generated text is ascii")
}

fn local_author_user_id(
    ctx: &CommandContext<'_>,
    workspace_id: WorkspaceId,
) -> Result<Option<crate::core::facts::FactId>, String> {
    Ok(
        auth::workspace::queries::local_membership(ctx.store(), workspace_id)?
            .map(|membership| membership.user_authority_fact_id),
    )
}

fn retained_floor_from_tombstones(
    ctx: &CommandContext<'_>,
    workspace_id: WorkspaceId,
) -> Result<u64, String> {
    queries::retained_floor_from_tombstones(ctx.store(), workspace_id)
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

// ---------------------------------------------------------------------------
// Local authoring capabilities (command boundary).
//
// Sending a message needs two local secrets: the endpoint signing key and the
// current local removal-frontier key. This is the command boundary that
// assembles those capabilities from already-projected local state. It is not a
// projector and it is not a query module for display state.
// ---------------------------------------------------------------------------

pub struct ContentMessageVault {
    signing: LocalSigningCapability,
    encryption: LocalEncryptionCapability,
}

impl ContentMessageVault {
    pub fn for_workspace(runtime: &Runtime, workspace_id: [u8; 32]) -> Result<Self, String> {
        let endpoint = auth::endpoint::create::local_endpoint(runtime.store())?
            .ok_or_else(|| "local endpoint is not initialized".to_string())?;
        auth::workspace::queries::local_membership(runtime.store(), workspace_id)?
            .ok_or_else(|| "local endpoint has not joined this workspace".to_string())?;
        let encryption = latest_local_key_secret(runtime, workspace_id)?;
        Ok(Self {
            signing: LocalSigningCapability {
                workspace_id,
                signer_id: endpoint.endpoint,
                public_key: endpoint.signing_public_key,
                private_key: endpoint.signing_secret,
            },
            encryption: LocalEncryptionCapability {
                workspace_id: encryption.workspace_id,
                frontier_id: encryption.frontier_id,
                owner_endpoint_id: encryption.owner_endpoint_id,
                created_at_ms: encryption.created_at_ms,
                key_secret: encryption.key_secret,
            },
        })
    }
}

impl IdentityVault for ContentMessageVault {
    fn local_signing_capability(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<LocalSigningCapability, String> {
        if self.signing.workspace_id == workspace_id {
            Ok(self.signing.clone())
        } else {
            Err("signing capability is not for requested workspace".to_string())
        }
    }

    fn local_encryption_capability(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<LocalEncryptionCapability, String> {
        if self.encryption.workspace_id == workspace_id {
            Ok(self.encryption.clone())
        } else {
            Err("encryption capability is not for requested workspace".to_string())
        }
    }
}

fn latest_local_key_secret(
    runtime: &Runtime,
    workspace_id: [u8; 32],
) -> Result<auth::local_key_secret::fact::LocalKeySecretFact, String> {
    runtime
        .facts()
        .filter_map(|fact| {
            auth::local_key_secret::layout::decode_local_key_secret(fact.body())
                .ok()
                .filter(|secret| secret.workspace_id == workspace_id)
        })
        .max_by(|left, right| {
            left.created_at_ms
                .cmp(&right.created_at_ms)
                .then_with(|| left.frontier_id.cmp(&right.frontier_id))
        })
        .ok_or_else(|| "no local key frontier is available for this workspace".to_string())
}

// ---------------------------------------------------------------------------
// Message retention (expiry, deletion, and floor support).
//
// Retention is the point where message state intentionally stops being a live
// row. These helpers decode either raw or signed message facts into the fields
// needed for expiration, write tombstones that preserve deletion history, and
// remove live message rows through the same atomic effect commit path used by
// normal projection. Message projection invokes them when matched context
// tells the message fact to self-delete.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageRetentionFact {
    pub workspace_id: FactId,
    pub created_at_ms: u64,
    pub author_user_id: FactId,
    pub frontier_id: FactId,
    pub minute: u64,
    pub expires_at_minute: u64,
}

pub trait RetentionMessageView {
    fn workspace_id(&self) -> FactId;
    fn created_at_ms(&self) -> u64;
    fn author_user_id(&self) -> FactId;
    fn frontier_id(&self) -> FactId;
    fn minute(&self) -> u64;
    fn expires_at_minute(&self) -> u64;
}

impl RetentionMessageView for MessageRetentionFact {
    fn workspace_id(&self) -> FactId {
        self.workspace_id
    }

    fn created_at_ms(&self) -> u64 {
        self.created_at_ms
    }

    fn author_user_id(&self) -> FactId {
        self.author_user_id
    }

    fn frontier_id(&self) -> FactId {
        self.frontier_id
    }

    fn minute(&self) -> u64 {
        self.minute
    }

    fn expires_at_minute(&self) -> u64 {
        self.expires_at_minute
    }
}

pub fn decode_message_fact(fact: &Fact) -> Result<MessageRetentionFact, String> {
    match fact.bytes.first().copied() {
        Some(layout::TYPE_CONTENT_MESSAGE) => {
            content_message_retention(layout::decode_fact(fact.body())?)
        }
        Some(signed_envelope::TYPE_SIGNED_ENVELOPE) => {
            let envelope = signed_envelope::decode_envelope(fact.body())?;
            match envelope.inner_type {
                layout::TYPE_CONTENT_MESSAGE => {
                    content_message_retention(layout::decode_fact(&envelope.payload)?)
                }
                _ => Err("signed envelope does not contain a message".to_string()),
            }
        }
        _ => Err("expected message fact".to_string()),
    }
}

/// Builds the keyed delete for a message row in `table`. This is a pure value
/// constructor used by message projection when expiry, deletion, or retention
/// context removes the target fact.
pub(crate) fn message_row_delete(
    table: TableName,
    workspace_id: FactId,
    message_id: FactId,
) -> TableDeleteWhere {
    TableDeleteWhere {
        table,
        columns: rows::MESSAGE_KEY_COLUMNS,
        values: vec![
            Value::Bytes(workspace_id.to_vec()),
            Value::Bytes(message_id.to_vec()),
        ],
    }
}

fn content_message_retention(
    message: message::fact::ContentMessageFact,
) -> Result<MessageRetentionFact, String> {
    Ok(MessageRetentionFact {
        workspace_id: message.workspace_id,
        created_at_ms: message.created_at_ms,
        author_user_id: message.author_user_id,
        frontier_id: message.frontier_id,
        minute: message.minute,
        expires_at_minute: message.expires_at_minute,
    })
}
