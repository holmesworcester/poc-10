//! Command-facing content-message workflows.
//!
//! Message facts keep their semantic content-message type. The user-visible
//! text is the encrypted field inside that fact, and projection opens it only
//! when matching key context is available. Commands gather runtime state,
//! call `author.rs`, self-check the authored fact, and return facts for
//! admission.

use crate::core::command::{AuthoredFacts, CommandClock, LocalEncryptionCapability, WorkspaceId};
use crate::core::db::Db;
use crate::core::facts::{Fact, FactId};
use crate::core::project_fact::ProjectionContext;
use crate::protocol::auth;
use crate::protocol::content::message::author;
use crate::protocol::content::message::fact::MAX_TEXT_BYTES;
use crate::protocol::content::message::queries;
use crate::protocol::content::{message, retention_policy};
use rusqlite::{params, OptionalExtension};

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

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthoredMessageFacts {
    message: Fact,
    signature: Fact,
}

struct MessageCommandAuthoring {
    snapshot: author::MessageAuthoringSnapshot,
    signer_private_key: crate::core::crypto::Ed25519PrivateKey,
}

pub fn send_message(
    store: &Db,
    clock: &dyn CommandClock,
    workspace_id: WorkspaceId,
    text: &str,
) -> Result<AuthoredFacts<SendReceipt>, String> {
    let created_at_ms = clock.next_timestamp();
    let facts = build_message_facts(store, workspace_id, text, created_at_ms)?;

    Ok(AuthoredFacts::new(SendReceipt {
        workspace_id,
        message_fact_id: facts.message.id,
        created_at_ms,
    })
    .with_facts(vec![facts.message, facts.signature]))
}

pub fn generate_messages(
    store: &Db,
    clock: &dyn CommandClock,
    workspace_id: WorkspaceId,
    count: usize,
    requested_message_text_bytes: usize,
) -> Result<AuthoredFacts<GenerateReceipt>, String> {
    if count == 0 {
        return Err("generate count must be positive".to_string());
    }
    if requested_message_text_bytes == 0 {
        return Err("generate message text size must be positive".to_string());
    }

    let first_timestamp = clock.next_timestamp();
    let last_timestamp = first_timestamp
        .checked_add((count - 1) as u64)
        .ok_or_else(|| "generate timestamp range overflows u64".to_string())?;
    let message_text_bytes = requested_message_text_bytes.min(MAX_TEXT_BYTES);
    let authoring = crate::core::perf_profile::measure_result("authoring_snapshot", || {
        prepare_authoring(store, workspace_id)
    })?;

    let mut facts = Vec::with_capacity(count.saturating_mul(2));
    let mut fact_ids = Vec::with_capacity(count);
    for index in 0..count {
        let timestamp = first_timestamp
            .checked_add(index as u64)
            .ok_or_else(|| "generate timestamp overflows u64".to_string())?;
        let text = crate::core::perf_profile::measure("generated_text", || {
            deterministic_generated_text(&workspace_id, timestamp, index, message_text_bytes)
        });
        let authored = crate::core::perf_profile::measure_result("message_fact_build", || {
            build_message_facts_from_authoring(&authoring, &text, timestamp)
        })?;
        fact_ids.push(authored.message.id);
        facts.push(authored.message);
        facts.push(authored.signature);
    }

    Ok(AuthoredFacts::new(GenerateReceipt {
        workspace_id,
        generated_facts: count,
        message_text_bytes,
        first_timestamp,
        last_timestamp,
        fact_ids,
    })
    .with_facts(facts))
}

fn prepare_authoring(
    store: &Db,
    workspace_id: WorkspaceId,
) -> Result<MessageCommandAuthoring, String> {
    let signing = auth::endpoint::api::local_signing_capability(store, workspace_id)?;
    let signer_private_key = signing.private_key;
    let encryption = local_encryption_capability(store, workspace_id)?;
    let author_user_id = local_author_user_id(store, workspace_id)?.unwrap_or(signing.signer_id);
    let active_policy = retention_policy::queries::active_for_workspace(store, workspace_id)?;
    let retained_floor_minute = retained_floor_from_tombstones(store, workspace_id)?;
    let snapshot = author::MessageAuthoringSnapshot::new(
        workspace_id,
        signing,
        encryption,
        author_user_id,
        active_policy,
        retained_floor_minute,
    )?;
    Ok(MessageCommandAuthoring {
        snapshot,
        signer_private_key,
    })
}

fn build_message_facts(
    store: &Db,
    workspace_id: WorkspaceId,
    text: &str,
    created_at_ms: u64,
) -> Result<AuthoredMessageFacts, String> {
    author::validate_message_text(text)?;
    let authoring = prepare_authoring(store, workspace_id)?;
    build_message_facts_from_authoring(&authoring, text, created_at_ms)
}

fn build_message_facts_from_authoring(
    authoring: &MessageCommandAuthoring,
    text: &str,
    created_at_ms: u64,
) -> Result<AuthoredMessageFacts, String> {
    let message = authoring.snapshot.build_message_fact(text, created_at_ms)?;
    let signature = auth::signature::author::sign_fact(
        authoring.snapshot.workspace_id(),
        &message,
        &authoring.signer_private_key,
        created_at_ms,
    )?;
    authenticate_content_message_fact(&message)?;
    authenticate_signature_fact(&signature)?;
    Ok(AuthoredMessageFacts { message, signature })
}

fn authenticate_content_message_fact(fact: &Fact) -> Result<(), String> {
    let decoded = super::project::decode::decode_fact(fact.body())?;
    super::project::authenticate::authenticate(fact, decoded, &ProjectionContext::default())
        .map(|_| ())
}

fn authenticate_signature_fact(fact: &Fact) -> Result<(), String> {
    let decoded = auth::signature::project::decode::decode_fact(fact.body())?;
    auth::signature::project::authenticate::authenticate(
        fact,
        decoded,
        &ProjectionContext::default(),
    )
    .map(|_| ())
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
    store: &Db,
    workspace_id: WorkspaceId,
) -> Result<Option<crate::core::facts::FactId>, String> {
    Ok(
        auth::workspace::queries::local_membership(store, workspace_id)?
            .map(|membership| membership.user_authority_fact_id),
    )
}

fn retained_floor_from_tombstones(store: &Db, workspace_id: WorkspaceId) -> Result<u64, String> {
    queries::retained_floor_from_tombstones(store, workspace_id)
}

// ---------------------------------------------------------------------------
// Local authoring capabilities (command boundary).
//
// Sending a message needs two local secrets: the endpoint signing key and the
// current local removal-frontier key. This is the command boundary that
// assembles those capabilities from already-projected local state. It is not a
// projector and it is not a query module for display state.
// ---------------------------------------------------------------------------

pub fn local_encryption_capability(
    store: &Db,
    workspace_id: WorkspaceId,
) -> Result<LocalEncryptionCapability, String> {
    let encryption = latest_local_key_secret(store, workspace_id)?;
    Ok(LocalEncryptionCapability {
        workspace_id: encryption.workspace_id,
        frontier_id: encryption.frontier_id,
        owner_endpoint_id: encryption.owner_endpoint_id,
        created_at_ms: encryption.created_at_ms,
        key_secret: encryption.key_secret,
    })
}

fn latest_local_key_secret(
    store: &Db,
    workspace_id: [u8; 32],
) -> Result<auth::local_key_secret::fact::LocalKeySecretFact, String> {
    store
        .conn()
        .query_row(
            "SELECT frontier_id, owner_endpoint_id, created_at_ms, key_secret
             FROM local_key_secret_rows
             WHERE workspace_id = ?1
             ORDER BY created_at_ms DESC, frontier_id DESC
             LIMIT 1",
            params![workspace_id],
            |row| {
                Ok(auth::local_key_secret::fact::LocalKeySecretFact {
                    workspace_id,
                    frontier_id: row.get(0)?,
                    owner_endpoint_id: row.get(1)?,
                    created_at_ms: row.get::<_, i64>(2)? as u64,
                    key_secret: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(|err| format!("load latest local key row: {err}"))?
        .ok_or_else(|| "no local key frontier is available for this workspace".to_string())
}

// ---------------------------------------------------------------------------
// Message retention (expiry, deletion, and floor support).
//
// Retention is the point where message state intentionally stops being a live
// row. These helpers decode signature-evidenced message facts into the fields needed for
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
    let message = super::project::decode::decode_fact(fact.body())?;
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
    use crate::core::command::FnClock;
    use crate::core::daemon::{self, RuntimeTurnHost};
    use crate::core::runtime::Runtime;
    use crate::protocol::app::{CONTEXT_PROTOCOL, CONTEXT_RUNTIME};

    fn drain_runtime_work_for_test(runtime: &mut Runtime, max_rounds: usize, limit: usize) {
        for _ in 0..max_rounds {
            runtime
                .drain_durable_projection(limit)
                .expect("drain durable projection batch");
            runtime
                .drain_incoming_projection(limit)
                .expect("drain incoming projection batch");
            runtime
                .drain_durable_intents(limit)
                .expect("drain durable intent batch");
            runtime
                .drain_local_intents(limit)
                .expect("drain local intent batch");
            if runtime.pending_projection_count() == 0 && runtime.pending_intent_count() == 0 {
                return;
            }
        }
        panic!("runtime work did not become idle within {max_rounds} rounds");
    }

    fn initialize_runtime_for_test(runtime: &mut Runtime) {
        let mut scheduler = daemon::RecurringScheduler::install(CONTEXT_RUNTIME.handlers);
        daemon::runtime_turn(
            CONTEXT_PROTOCOL.daemon,
            runtime,
            RuntimeTurnHost::local(),
            &mut scheduler,
            512,
        )
        .expect("runtime turn");
    }

    #[test]
    fn generate_messages_reuses_store_queried_authoring_snapshot() {
        let mut runtime = Runtime::open_memory(&CONTEXT_RUNTIME).expect("runtime");
        initialize_runtime_for_test(&mut runtime);
        let workspace_clock = FnClock(|| 1_000);
        let workspace = crate::protocol::auth::workspace::api::create_workspace_with_identity(
            runtime.db(),
            &workspace_clock,
            "test",
            crate::protocol::auth::workspace::api::BootstrapIdentity {
                username: "alice",
                device_name: "laptop",
                ttl_minutes: Some(0),
            },
        )
        .expect("workspace command");
        let workspace_id = workspace.receipt.workspace_fact_id;
        runtime
            .submit_authored_facts(workspace)
            .expect("submit workspace");
        drain_runtime_work_for_test(&mut runtime, 8, 512);
        let frontier = crate::protocol::auth::key_wrap::api::create_key_frontier(
            runtime.db(),
            crate::protocol::auth::key_wrap::api::CreateKeyFrontier {
                created_at_ms: 2_000,
                workspace_id,
            },
        )
        .expect("frontier command");
        runtime
            .submit_authored_facts(frontier)
            .expect("submit frontier");
        drain_runtime_work_for_test(&mut runtime, 8, 512);
        let message_clock = FnClock(|| 10_000);

        let output = generate_messages(runtime.db(), &message_clock, workspace_id, 4, 32)
            .expect("generate messages");
        let membership =
            crate::protocol::auth::workspace::queries::local_membership(runtime.db(), workspace_id)
                .expect("membership query")
                .expect("local membership");
        let signing = crate::protocol::auth::endpoint::api::local_signing_capability(
            runtime.db(),
            workspace_id,
        )
        .expect("local signing");
        let encryption =
            local_encryption_capability(runtime.db(), workspace_id).expect("local encryption");

        assert_eq!(output.facts.len(), 8);
        for (index, facts) in output.facts.chunks_exact(2).enumerate() {
            let message_fact = &facts[0];
            let signature_fact = &facts[1];
            assert_eq!(message_fact.timestamp, 10_000 + index as u64);
            assert_eq!(signature_fact.timestamp, message_fact.timestamp);
            let message = crate::protocol::content::message::project::decode::decode_fact(
                message_fact.body(),
            )
            .expect("decode message");
            let signature = crate::protocol::auth::signature::project::decode::decode_fact(
                signature_fact.body(),
            )
            .expect("decode signature");
            assert_eq!(signature.target_fact_id, message_fact.id);
            crate::protocol::auth::signature::project::authenticate::prove_signature_evidence(
                &signature,
            )
            .expect("valid signature evidence");
            assert_eq!(message.workspace_id, workspace_id);
            assert_eq!(message.author_user_id, membership.user_authority_fact_id);
            assert_eq!(message.signer_id, signing.signer_id);
            assert_eq!(message.frontier_id, encryption.frontier_id);
        }
    }
}
