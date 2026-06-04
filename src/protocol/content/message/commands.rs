//! Command-facing content-message workflows.
//!
//! Message facts keep their semantic content-message type. The user-visible
//! text is the encrypted field inside that fact, and projection opens it only
//! when matching key context is available. Commands gather runtime state,
//! call `author.rs`, self-check the authored fact, and return facts for
//! admission.

use crate::core::command_context::{
    CommandContext, CommandOutput, IdentityVault, LocalEncryptionCapability,
    LocalSigningCapability, WorkspaceId,
};
use crate::core::facts::{Fact, FactId};
use crate::core::projectors::authenticate_authored;
use crate::core::runtime::Runtime;
use crate::protocol::auth;
use crate::protocol::content::message::author;
use crate::protocol::content::message::fact::MAX_TEXT_BYTES;
use crate::protocol::content::message::queries;
use crate::protocol::content::{message, retention_policy};

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
    let authoring = crate::core::perf_profile::measure_result("authoring_snapshot", || {
        prepare_authoring_snapshot(ctx, workspace_id)
    })?;

    let mut facts = Vec::with_capacity(count);
    let mut fact_ids = Vec::with_capacity(count);
    for index in 0..count {
        let timestamp = first_timestamp
            .checked_add(index as u64)
            .ok_or_else(|| "generate timestamp overflows u64".to_string())?;
        let text = crate::core::perf_profile::measure("generated_text", || {
            deterministic_generated_text(&workspace_id, timestamp, index, message_text_bytes)
        });
        let fact = crate::core::perf_profile::measure_result("message_fact_build", || {
            authoring.build_message_fact(&text, timestamp)
        })?;
        authenticate_authored::<super::authenticate::ContentMessageAuthenticator>(&fact)?;
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

fn prepare_authoring_snapshot(
    ctx: &CommandContext<'_>,
    workspace_id: WorkspaceId,
) -> Result<author::MessageAuthoringSnapshot, String> {
    let signing = ctx.local_signing_capability(workspace_id)?;
    let encryption = ctx.local_encryption_capability(workspace_id)?;
    let author_user_id = local_author_user_id(ctx, workspace_id)?.unwrap_or(signing.signer_id);
    let active_policy = retention_policy::queries::active_for_workspace(ctx.store(), workspace_id)?;
    let retained_floor_minute = retained_floor_from_tombstones(ctx, workspace_id)?;
    author::MessageAuthoringSnapshot::new(
        workspace_id,
        signing,
        encryption,
        author_user_id,
        active_policy,
        retained_floor_minute,
    )
}

fn build_message_fact(
    ctx: &CommandContext<'_>,
    workspace_id: WorkspaceId,
    text: &str,
    created_at_ms: u64,
) -> Result<Fact, String> {
    author::validate_message_text(text)?;
    let fact =
        prepare_authoring_snapshot(ctx, workspace_id)?.build_message_fact(text, created_at_ms)?;
    authenticate_authored::<super::authenticate::ContentMessageAuthenticator>(&fact)?;
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
// row. These helpers decode signed message facts into the fields needed for
// expiration, write tombstones that preserve deletion history, and remove live
// message rows through the same atomic effect commit path used by normal
// projection. Message projection invokes them when matched context tells the
// message fact to self-delete.
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
    let message = super::decode::decode_fact(fact.body())?;
    super::authenticate::verify_signature(&message)?;
    content_message_retention(message)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::command_context::FnClock;
    use crate::core::crypto;
    use crate::core::schema::CORE_SCHEMA_SOURCE;
    use crate::core::store::Store;
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;
    use std::cell::Cell;

    struct CountingVault {
        signer_id: FactId,
        private_key: crypto::Ed25519PrivateKey,
        encryption_key: crypto::XChaCha20Poly1305Key,
        signing_calls: Cell<usize>,
        encryption_calls: Cell<usize>,
    }

    impl CountingVault {
        fn new() -> Self {
            Self {
                signer_id: [2; 32],
                private_key: [7; 32],
                encryption_key: [9; 32],
                signing_calls: Cell::new(0),
                encryption_calls: Cell::new(0),
            }
        }
    }

    impl IdentityVault for CountingVault {
        fn local_signing_capability(
            &self,
            workspace_id: WorkspaceId,
        ) -> Result<LocalSigningCapability, String> {
            self.signing_calls.set(self.signing_calls.get() + 1);
            Ok(LocalSigningCapability {
                workspace_id,
                signer_id: self.signer_id,
                public_key: crypto::ed25519_public_key(&self.private_key),
                private_key: self.private_key,
            })
        }

        fn local_encryption_capability(
            &self,
            workspace_id: WorkspaceId,
        ) -> Result<LocalEncryptionCapability, String> {
            self.encryption_calls.set(self.encryption_calls.get() + 1);
            Ok(LocalEncryptionCapability {
                workspace_id,
                frontier_id: [3; 32],
                owner_endpoint_id: [4; 32],
                created_at_ms: 1,
                key_secret: self.encryption_key,
            })
        }
    }

    #[test]
    fn generate_messages_reuses_command_local_authoring_snapshot() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("store");
        let workspace_id = [1; 32];
        let clock = FnClock(|| 10_000);
        let vault = CountingVault::new();
        let ctx = CommandContext::new(&store, &clock, &vault);

        let output = generate_messages(&ctx, workspace_id, 4, 32).expect("generate messages");

        assert_eq!(vault.signing_calls.get(), 1);
        assert_eq!(vault.encryption_calls.get(), 1);
        assert_eq!(output.effects.facts.len(), 4);
        for (index, fact) in output.effects.facts.iter().enumerate() {
            assert_eq!(fact.timestamp, 10_000 + index as u64);
            let message = crate::protocol::content::message::decode::decode_fact(fact.body())
                .expect("decode message");
            crate::protocol::content::message::authenticate::verify_signature(&message)
                .expect("valid signature");
            assert_eq!(message.workspace_id, workspace_id);
            assert_eq!(message.author_user_id, vault.signer_id);
            assert_eq!(message.signer_id, vault.signer_id);
            assert_eq!(message.frontier_id, [3; 32]);
        }
    }
}
