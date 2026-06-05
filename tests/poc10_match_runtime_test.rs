//! Target runtime facade tests.

use std::{cell::Cell, collections::BTreeSet};

use topo::core::command_context::{
    CommandClock, IdentityVault, LocalEncryptionCapability, LocalSigningCapability, WorkspaceId,
};
use topo::core::crypto;
use topo::core::facts::{Fact, FactScope, ScopeKind};
use topo::core::runtime::Runtime;
use topo::protocol::app::MATCH_RUNTIME;
use topo::protocol::auth::local_key_secret::encode as local_key_secret_layout;
use topo::protocol::auth::local_key_secret::fact::LocalKeySecretFact;
use topo::protocol::auth::removal_frontier::encode as removal_frontier_layout;
use topo::protocol::auth::removal_frontier::fact::RemovalFrontierFact;
use topo::protocol::auth::workspace::{
    commands::{create_workspace_with_identity, BootstrapIdentity},
    queries as workspace_queries,
};
use topo::protocol::content::message as content_message;

struct FixedClock(Cell<u64>);

impl CommandClock for FixedClock {
    fn next_timestamp(&self) -> u64 {
        let next = self.0.get();
        self.0.set(next + 1);
        next
    }
}

struct EmptyVault;

impl IdentityVault for EmptyVault {
    fn local_signing_capability(
        &self,
        _workspace_id: WorkspaceId,
    ) -> Result<LocalSigningCapability, String> {
        Err("no signing capability".to_string())
    }

    fn local_encryption_capability(
        &self,
        _workspace_id: WorkspaceId,
    ) -> Result<LocalEncryptionCapability, String> {
        Err("no encryption capability".to_string())
    }
}

#[test]
fn runtime_submits_command_output_and_projects_workspace_rows() {
    let mut runtime = Runtime::open_memory(&MATCH_RUNTIME).expect("runtime");
    let clock = FixedClock(Cell::new(123_000));
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        create_workspace_with_identity(
            &ctx,
            "Runtime",
            BootstrapIdentity {
                username: "alice",
                device_name: "laptop",
                ttl_minutes: Some(0),
            },
        )
        .expect("create workspace")
    };

    let receipt = runtime
        .submit_command_output(output)
        .expect("submit command output");
    let status = runtime
        .process_projection_until_idle(4, 32)
        .expect("drain projection");

    assert_eq!(receipt.created_at_ms, 123_000);
    assert!(status.progressed);
    assert!(
        runtime.pending_intent_count() >= 1,
        "workspace projection should enqueue sync maintenance work"
    );

    assert_eq!(
        workspace_queries::count_workspaces(runtime.store()).expect("workspace row count"),
        1
    );
    let workspace = workspace_queries::workspace_by_id(runtime.store(), receipt.workspace_fact_id)
        .expect("row");
    assert_eq!(workspace.name, "Runtime");
}

#[test]
fn runtime_routes_signed_content_message_to_content_message_projector() {
    let workspace_id = [42; 32];
    let signer_id = [11; 32];
    let signer_private = [7; 32];
    let frontier = removal_frontier_fact(workspace_id, [33; 32]);
    let frontier_id = frontier.id;
    let key_secret = [9; crypto::XCHACHA20_POLY1305_KEY_BYTES];
    let message = signed_content_message_fact(SignedContentMessageInput {
        workspace_id,
        author_user_id: [44; 32],
        signer_id,
        signer_private: &signer_private,
        frontier_id,
        key_secret,
        created_at_ms: 60_000,
        text: "runtime signed message",
    });
    let mut runtime = Runtime::open_memory(&MATCH_RUNTIME).expect("runtime");

    runtime.submit_fact(frontier);
    runtime.submit_fact(local_key_secret_fact(
        workspace_id,
        frontier_id,
        [33; 32],
        key_secret,
    ));
    runtime.submit_fact(message);
    let status = runtime
        .process_projection_until_idle(8, 64)
        .expect("drain signed message projection");

    assert!(status.progressed);
    assert!(
        content_message::queries::content_message_rows(runtime.store(), workspace_id)
            .expect("content message rows")
            .is_empty(),
        "content rows wait until author context is available"
    );
    assert!(
        content_message::queries::opened_messages(runtime.store(), workspace_id)
            .expect("opened message rows")
            .is_empty(),
        "opened rows wait until author context is available"
    );
    assert!(
        runtime.pending_intent_count() > 0,
        "semantic content message should still be made shareable while waiting"
    );
}

#[test]
fn runtime_dispatches_every_protocol_handler_registration() {
    let dispatched = MATCH_RUNTIME
        .handlers
        .iter()
        .map(|handler| handler.name.to_string())
        .collect::<BTreeSet<_>>();

    assert!(
        dispatched
            .iter()
            .all(|handler| !handler.starts_with("purge_") || !handler.contains("message")),
        "message/content deletion should be projector-owned, not handler-owned"
    );
    assert!(
        dispatched.len() == MATCH_RUNTIME.handlers.len(),
        "HANDLER_ROUTES must not contain duplicate runtime handler names"
    );
}

fn removal_frontier_fact(workspace_id: [u8; 32], owner_endpoint_id: [u8; 32]) -> Fact {
    let signing_key = [5; 32];
    let mut body = RemovalFrontierFact {
        workspace_id,
        owner_endpoint_id,
        created_at_ms: 1,
        signer_public_key: crypto::ed25519_public_key(&signing_key),
        signature: [0; crypto::ED25519_SIGNATURE_BYTES],
    };
    body.signature = crypto::ed25519_sign(
        &signing_key,
        &topo::protocol::canonical::encode_with_zeroed_trailing_signature(
            &body,
            removal_frontier_layout::encode_removal_frontier,
        )
        .expect("frontier signing bytes"),
    );
    Fact::new(
        workspace_scope(workspace_id),
        1,
        removal_frontier_layout::encode_removal_frontier(&body).expect("encode removal frontier"),
    )
}

fn local_key_secret_fact(
    workspace_id: [u8; 32],
    frontier_id: [u8; 32],
    owner_endpoint_id: [u8; 32],
    key_secret: [u8; crypto::XCHACHA20_POLY1305_KEY_BYTES],
) -> Fact {
    Fact::new(
        FactScope::Local,
        1,
        local_key_secret_layout::encode_local_key_secret(&LocalKeySecretFact {
            workspace_id,
            frontier_id,
            owner_endpoint_id,
            created_at_ms: 1,
            key_secret,
        })
        .expect("encode local key secret"),
    )
}

struct SignedContentMessageInput<'a> {
    workspace_id: [u8; 32],
    author_user_id: [u8; 32],
    signer_id: [u8; 32],
    signer_private: &'a [u8; 32],
    frontier_id: [u8; 32],
    key_secret: [u8; crypto::XCHACHA20_POLY1305_KEY_BYTES],
    created_at_ms: u64,
    text: &'a str,
}

fn signed_content_message_fact(input: SignedContentMessageInput<'_>) -> Fact {
    let minute = input.created_at_ms / 60_000;
    let nonce = [7; content_message::fact::NONCE_BYTES];
    let plaintext =
        content_message::author::pad_plaintext(input.text.as_bytes()).expect("pad text");
    let ciphertext = crypto::xchacha20poly1305_encrypt(
        &input.key_secret,
        &content_message::author::associated_data(input.workspace_id, input.frontier_id, minute),
        &nonce,
        &plaintext,
    )
    .expect("encrypt message");
    let mut body = content_message::fact::ContentMessageFact {
        workspace_id: input.workspace_id,
        created_at_ms: input.created_at_ms,
        author_user_id: input.author_user_id,
        signer_id: input.signer_id,
        signer_public_key: crypto::ed25519_public_key(input.signer_private),
        frontier_id: input.frontier_id,
        local_history_node_secret_id: [0; 32],
        expires_at_minute: u64::MAX,
        retention_policy_id: [0; 32],
        minute,
        nonce,
        ciphertext: content_message::fact::MessageCiphertext::new(&ciphertext).expect("ciphertext"),
        signature: [0; crypto::ED25519_SIGNATURE_BYTES],
    };
    body.signature = crypto::ed25519_sign(
        input.signer_private,
        &topo::protocol::canonical::encode_with_zeroed_trailing_signature(
            &body,
            content_message::encode::encode_fact,
        )
        .expect("message signing bytes"),
    );
    let bytes = content_message::encode::encode_fact(&body).expect("encode content message");
    Fact::new(
        workspace_scope(input.workspace_id),
        input.created_at_ms,
        bytes,
    )
}

fn workspace_scope(workspace_id: [u8; 32]) -> FactScope {
    FactScope::Scoped {
        kind: ScopeKind::new("workspace").expect("valid workspace scope"),
        id: workspace_id,
    }
}
