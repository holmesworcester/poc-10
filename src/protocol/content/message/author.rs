//! Pure content-message fact authoring.
//!
//! This layer takes an explicit authoring snapshot plus message text, derives
//! crypto material from typed inputs, encrypts, encodes bytes, and returns a
//! target fact. Runtime gathering and signature evidence belong in
//! `commands.rs`.

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
use crate::protocol::{root, sealed_payload};

#[derive(Clone)]
pub struct MessageAuthoringSnapshot {
    workspace_id: WorkspaceId,
    signer_id: FactId,
    encryption: LocalEncryptionCapability,
    signer_public_key: crypto::Ed25519PublicKey,
    author_user_id: FactId,
    active_policy: Option<retention_policy::queries::RetentionPolicyRow>,
    retained_floor_minute: u64,
}

pub struct RootPayloadMessageFacts {
    pub root: Fact,
    pub payload: Fact,
}

struct EncryptedMessageParts {
    minute: u64,
    expires_at_minute: u64,
    retention_policy_id: FactId,
    nonce: [u8; NONCE_BYTES],
    ciphertext: Vec<u8>,
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
            signer_id: signing.signer_id,
            encryption,
            author_user_id,
            active_policy,
            retained_floor_minute,
        })
    }

    pub fn workspace_id(&self) -> WorkspaceId {
        self.workspace_id
    }

    pub fn build_message_fact(&self, text: &str, created_at_ms: u64) -> Result<Fact, String> {
        let encrypted = self.encrypt_message_parts(text, created_at_ms)?;

        let message = ContentMessageFact {
            workspace_id: self.workspace_id,
            created_at_ms,
            author_user_id: self.author_user_id,
            signer_id: self.signer_id,
            signer_public_key: self.signer_public_key,
            frontier_id: self.encryption.frontier_id,
            local_history_node_secret_id: [0; 32],
            expires_at_minute: encrypted.expires_at_minute,
            retention_policy_id: encrypted.retention_policy_id,
            minute: encrypted.minute,
            nonce: encrypted.nonce,
            ciphertext: MessageCiphertext::new(&encrypted.ciphertext)
                .map_err(|err| format!("content message ciphertext: {err}"))?,
        };

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

    pub fn build_message_root_payload_facts(
        &self,
        text: &str,
        created_at_ms: u64,
    ) -> Result<RootPayloadMessageFacts, String> {
        let encrypted = self.encrypt_message_parts(text, created_at_ms)?;
        let payload_body = sealed_payload::fact::SealedPayloadFact {
            format: super::PAYLOAD_FORMAT_MESSAGE_TEXT,
            algorithm: super::PAYLOAD_ALGORITHM_XCHACHA20_POLY1305,
            header: sealed_payload::fact::PayloadHeader::new(&encrypted.nonce)
                .map_err(|err| format!("message payload nonce header: {err}"))?,
            ciphertext: sealed_payload::fact::PayloadCiphertext::new(&encrypted.ciphertext)
                .map_err(|err| format!("message payload ciphertext: {err}"))?,
        };
        let payload = Fact::new(
            FactScope::Global,
            created_at_ms,
            sealed_payload::encode::encode_fact(&payload_body)?,
        );

        let mut refs = vec![
            root::fact::RootRef::new(root::roles::WORKSPACE, 0, self.workspace_id)?,
            root::fact::RootRef::new(root::roles::AUTHOR, 0, self.author_user_id)?,
            root::fact::RootRef::new(root::roles::SIGNER, 0, self.signer_id)?,
            root::fact::RootRef::new(root::roles::KEY_DOMAIN, 0, self.encryption.frontier_id)?,
            root::fact::RootRef::new(root::roles::CONTENT, 0, payload.id)?,
        ];
        if encrypted.retention_policy_id != [0; 32] {
            refs.push(root::fact::RootRef::new(
                root::roles::POLICY,
                0,
                encrypted.retention_policy_id,
            )?);
        }
        refs.sort_by_key(|edge| (edge.role, edge.index));

        let root_body = root::fact::RootFact {
            family: super::ROOT_FAMILY_CONTENT_MESSAGE,
            version: super::ROOT_VERSION_CONTENT_MESSAGE,
            created_at_ms,
            refs,
        };
        let root = Fact::new(
            crate::protocol::auth::workspace::scope(self.workspace_id),
            created_at_ms,
            root::encode::encode_fact(&root_body)?,
        );

        Ok(RootPayloadMessageFacts { root, payload })
    }

    fn encrypt_message_parts(
        &self,
        text: &str,
        created_at_ms: u64,
    ) -> Result<EncryptedMessageParts, String> {
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

        let nonce = deterministic_nonce(self.workspace_id, self.signer_id, created_at_ms);
        let plaintext = pad_plaintext(text.as_bytes())?;
        let ciphertext = crate::core::perf_profile::measure_result("message_encrypt", || {
            crypto::xchacha20poly1305_encrypt(
                &self.encryption.key_secret,
                &super::encode::associated_data(
                    self.workspace_id,
                    self.encryption.frontier_id,
                    minute,
                ),
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
        Ok(EncryptedMessageParts {
            minute,
            expires_at_minute,
            retention_policy_id,
            nonce,
            ciphertext,
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

#[cfg(test)]
mod tests {
    use crate::core::command_context::{LocalEncryptionCapability, LocalSigningCapability};
    use crate::core::crypto;
    use crate::protocol::content::message::decode::recover_text;

    use super::*;

    fn snapshot() -> MessageAuthoringSnapshot {
        let workspace_id = [1; 32];
        MessageAuthoringSnapshot::new(
            workspace_id,
            LocalSigningCapability {
                workspace_id,
                signer_id: [3; 32],
                public_key: crypto::ed25519_public_key(&[9; 32]),
                private_key: [9; 32],
            },
            LocalEncryptionCapability {
                workspace_id,
                frontier_id: [4; 32],
                owner_endpoint_id: [3; 32],
                created_at_ms: 1,
                key_secret: [7; 32],
            },
            [2; 32],
            None,
            0,
        )
        .expect("snapshot")
    }

    #[test]
    fn message_root_payload_authoring_keeps_content_out_of_root() {
        let snapshot = snapshot();
        let created_at_ms = 180_000;
        let authored = snapshot
            .build_message_root_payload_facts("hello root", created_at_ms)
            .expect("root payload message");

        let root =
            crate::protocol::root::decode_fact_payload(authored.root.body()).expect("decode root");
        assert_eq!(root.family, super::super::ROOT_FAMILY_CONTENT_MESSAGE);
        assert_eq!(root.version, super::super::ROOT_VERSION_CONTENT_MESSAGE);
        assert_eq!(root.created_at_ms, created_at_ms);
        assert_eq!(
            root.ref_by_role_index(crate::protocol::root::roles::WORKSPACE, 0)
                .expect("workspace ref")
                .target_fact_id,
            [1; 32]
        );
        assert_eq!(
            root.ref_by_role_index(crate::protocol::root::roles::CONTENT, 0)
                .expect("content ref")
                .target_fact_id,
            authored.payload.id
        );

        let payload = crate::protocol::sealed_payload::decode_fact_payload(authored.payload.body())
            .expect("decode payload");
        assert_eq!(payload.format, super::super::PAYLOAD_FORMAT_MESSAGE_TEXT);
        assert_eq!(
            payload.algorithm,
            super::super::PAYLOAD_ALGORITHM_XCHACHA20_POLY1305
        );
        assert_eq!(payload.header.len(), NONCE_BYTES);

        let nonce: [u8; NONCE_BYTES] = payload.header.bytes().try_into().expect("nonce header");
        let plaintext = crypto::xchacha20poly1305_decrypt(
            &[7; 32],
            &crate::protocol::content::message::encode::associated_data(
                [1; 32],
                [4; 32],
                created_at_ms / UNIX_MINUTE_MS,
            ),
            &nonce,
            payload.ciphertext.bytes(),
        )
        .expect("decrypt payload");
        assert_eq!(
            recover_text(&plaintext).expect("recover text"),
            "hello root"
        );
    }
}
