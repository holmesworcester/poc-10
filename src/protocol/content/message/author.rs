//! Building a message fact from an authoring snapshot.
//!
//! Given a gathered snapshot — the workspace's signing and encryption
//! capabilities, the active retention policy, and the retained floor — plus the
//! message text, this derives the AEAD nonce and associated data via `encode`'s
//! transcripts, encrypts the text, signs the canonical envelope, encodes the
//! fact, and self-authenticates it (the write pipeline's exit gate).
//! `commands.rs` gathers the snapshot and calls in here.

use crate::core::command_context::{
    LocalEncryptionCapability, LocalSigningCapability, WorkspaceId,
};
use crate::core::crypto;
use crate::core::facts::{Fact, FactId, FactScope, ScopeKind};
use crate::core::projectors::authenticate_authored;
use crate::protocol::content::retention_policy;

use super::authenticate::ContentMessageAuthenticator;
use super::encode;
use super::fact::{
    ContentMessageFact, MessageCiphertext, CIPHERTEXT_BYTES, MAX_TEXT_BYTES, UNIX_MINUTE_MS,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendReceipt {
    pub workspace_id: WorkspaceId,
    pub message_fact_id: FactId,
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

/// Gathered local authoring inputs. `commands.rs` builds this from the runtime;
/// `author` consumes it without any further context.
pub struct MessageAuthoringSnapshot {
    pub(crate) workspace_id: WorkspaceId,
    pub(crate) signing: LocalSigningCapability,
    pub(crate) encryption: LocalEncryptionCapability,
    pub(crate) signer_public_key: crypto::Ed25519PublicKey,
    pub(crate) author_user_id: FactId,
    pub(crate) active_policy: Option<retention_policy::rows::RetentionPolicyRow>,
    pub(crate) retained_floor_minute: u64,
}

impl MessageAuthoringSnapshot {
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

        let nonce =
            encode::deterministic_nonce(self.workspace_id, self.signing.signer_id, created_at_ms);
        let plaintext = encode::pad_plaintext(text.as_bytes())?;
        let ciphertext = crypto::xchacha20poly1305_encrypt(
            &self.encryption.key_secret,
            &encode::associated_data(self.workspace_id, self.encryption.frontier_id, minute),
            &nonce,
            &plaintext,
        )?;
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
        let (_, signature) = crypto::ed25519_sign_canonical(
            &self.signing.private_key,
            &encode::signing_bytes(&message)?,
        );
        message.signature = signature;

        let fact = Fact::new(
            FactScope::Scoped {
                kind: ScopeKind::new("workspace").expect("valid workspace scope"),
                id: self.workspace_id,
            },
            created_at_ms,
            encode::encode_fact(&message)?,
        );
        // Write-pipeline exit gate: never emit a fact we cannot authenticate.
        authenticate_authored::<ContentMessageAuthenticator>(&fact)?;
        Ok(fact)
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
