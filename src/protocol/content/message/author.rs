//! Pure content-message fact authoring.
//!
//! This layer takes an explicit authoring snapshot plus message text, derives
//! crypto material from canonical bytes, signs/encrypts, encodes bytes,
//! and returns a fact. Runtime gathering belongs in `commands.rs`.

use crate::core::command_context::{
    LocalEncryptionCapability, LocalSigningCapability, WorkspaceId,
};
use crate::core::crypto::{self, XChaCha20Poly1305Nonce};
use crate::core::facts::{Fact, FactId, FactScope, ScopeKind};
use crate::core::wire;
use crate::protocol::content::message::fact::{
    ContentMessageFact, MessageCiphertext, CIPHERTEXT_BYTES, MAX_TEXT_BYTES, NONCE_BYTES,
    PLAINTEXT_SLOT_BYTES, TEXT_LENGTH_PREFIX_BYTES, UNIX_MINUTE_MS,
};
use crate::protocol::content::retention_policy;

#[derive(Clone)]
pub struct MessageAuthoringSnapshot {
    workspace_id: WorkspaceId,
    signing: LocalSigningCapability,
    encryption: LocalEncryptionCapability,
    signer_public_key: crypto::Ed25519PublicKey,
    author_user_id: FactId,
    active_policy: Option<retention_policy::queries::RetentionPolicyRow>,
    retained_floor_minute: u64,
}

impl MessageAuthoringSnapshot {
    pub fn new(
        workspace_id: WorkspaceId,
        signing: LocalSigningCapability,
        encryption: LocalEncryptionCapability,
        author_user_id: FactId,
        active_policy: Option<retention_policy::queries::RetentionPolicyRow>,
        retained_floor_minute: u64,
    ) -> Result<Self, String> {
        if signing.workspace_id != workspace_id {
            return Err("signing capability is not bound to this workspace".to_string());
        }
        if encryption.workspace_id != workspace_id {
            return Err("encryption capability is not bound to this workspace".to_string());
        }

        Ok(Self {
            workspace_id,
            signer_public_key: crypto::ed25519_public_key(&signing.private_key),
            signing,
            encryption,
            author_user_id,
            active_policy,
            retained_floor_minute,
        })
    }

    pub fn build_message_fact(&self, text: &str, created_at_ms: u64) -> Result<Fact, String> {
        validate_message_text(text)?;

        let minute = created_at_ms / UNIX_MINUTE_MS;
        if let Some(policy) = &self.active_policy {
            if minute < policy.retire_minute {
                return Err(
                    "send_message minute is below the active disappearing floor".to_string()
                );
            }
        }
        if minute < self.retained_floor_minute {
            return Err("no retained ancestor covers message minute".to_string());
        }
        let expires_at_minute = self
            .active_policy
            .as_ref()
            .map(|policy| minute.saturating_add(u64::from(policy.ttl_minutes)))
            .unwrap_or(u64::MAX);
        let retention_policy_id = self
            .active_policy
            .as_ref()
            .map(|policy| policy.policy_id)
            .unwrap_or([0; 32]);

        let nonce = deterministic_nonce(self.workspace_id, self.signing.signer_id, created_at_ms);
        let plaintext = pad_plaintext(text.as_bytes())?;
        let ciphertext = crate::core::perf_profile::measure_result("message_encrypt", || {
            crypto::xchacha20poly1305_encrypt(
                &self.encryption.key_secret,
                &associated_data(self.workspace_id, self.encryption.frontier_id, minute),
                &nonce,
                &plaintext,
            )
        })?;
        if ciphertext.len() != CIPHERTEXT_BYTES {
            return Err(format!(
                "content message ciphertext is {} bytes, expected {CIPHERTEXT_BYTES}",
                ciphertext.len()
            ));
        }

        let mut message = ContentMessageFact {
            workspace_id: self.workspace_id,
            created_at_ms,
            author_user_id: self.author_user_id,
            signer_id: self.signing.signer_id,
            signer_public_key: self.signer_public_key,
            frontier_id: self.encryption.frontier_id,
            local_history_node_secret_id: [0; 32],
            expires_at_minute,
            retention_policy_id,
            minute,
            nonce,
            ciphertext: MessageCiphertext::new(&ciphertext)
                .map_err(|err| format!("content message ciphertext: {err}"))?,
            signature: [0; crypto::ED25519_SIGNATURE_BYTES],
        };
        let (_, signature) = crate::core::perf_profile::measure_result("message_sign", || {
            Ok::<_, String>(crypto::ed25519_sign_canonical(
                &self.signing.private_key,
                &crate::protocol::canonical::encode_with_zeroed_trailing_signature(
                    &message,
                    super::encode::encode_fact,
                )?,
            ))
        })?;
        message.signature = signature;

        crate::core::perf_profile::measure_result("message_encode", || {
            Ok::<_, String>(Fact::new(
                FactScope::Scoped {
                    kind: ScopeKind::new("workspace").expect("valid workspace scope"),
                    id: self.workspace_id,
                },
                created_at_ms,
                super::encode::encode_fact(&message)?,
            ))
        })
    }
}

pub fn validate_message_text(text: &str) -> Result<(), String> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("send_message text must not be blank".to_string());
    }
    if text.len() > MAX_TEXT_BYTES {
        return Err(format!(
            "send_message text exceeds {MAX_TEXT_BYTES} byte encrypted slot"
        ));
    }
    Ok(())
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

pub fn associated_data(workspace_id: WorkspaceId, frontier_id: FactId, minute: u64) -> Vec<u8> {
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
    let mut nonce = [0u8; NONCE_BYTES];
    nonce.copy_from_slice(&hash[..NONCE_BYTES]);
    nonce
}
