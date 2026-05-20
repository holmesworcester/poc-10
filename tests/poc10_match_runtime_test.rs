//! Target runtime facade tests.

use std::{cell::Cell, collections::BTreeSet, path::Path};

use topo::core::command_context::{
    CommandClock, IdentityVault, LocalEncryptionCapability, LocalSigningCapability, WorkspaceId,
};
use topo::core::crypto;
use topo::core::facts::{Fact, FactScope, ScopeKind};
use topo::protocol::facts::content::message as content_message;
use topo::protocol::facts::encryption::{
    fact::{LocalKeySecretFact, RemovalFrontierFact},
    layout as encryption_layout,
};
use topo::protocol::facts::identity::signed_fact::create as signed_fact_create;
use topo::protocol::facts::identity::workspace::{
    commands::create_workspace, rows as workspace_rows,
};
use topo::protocol::registry::PROTOCOL;
use topo::protocol::runtime::ProtocolRuntime;

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
    let mut runtime = ProtocolRuntime::open_memory().expect("runtime");
    let clock = FixedClock(Cell::new(123_000));
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        create_workspace(&ctx, [9; 32], "Runtime").expect("create workspace")
    };

    let receipt = runtime
        .submit_command_output(output)
        .expect("submit command output");
    let status = runtime
        .process_projection_until_idle(4, 32)
        .expect("drain projection");

    assert_eq!(receipt.created_at_ms, 123_000);
    assert!(status.progressed);
    assert_eq!(runtime.pending_intent_count(), 1);

    let rows = runtime
        .store()
        .table_rows(workspace_rows::WORKSPACE_ROWS)
        .expect("workspace rows");
    assert_eq!(rows.len(), 1);
    let row = workspace_rows::decode_workspace_row(&rows[0].0, &rows[0].1).expect("decode row");
    assert_eq!(row.name, "Runtime");
    assert_eq!(row.public_key, [9; 32]);
}

#[test]
fn runtime_routes_signed_content_message_to_content_message_projector() {
    let workspace_id = [42; 32];
    let signer_id = [11; 32];
    let signer_private = [7; 32];
    let frontier = removal_frontier_fact(workspace_id, [33; 32]);
    let frontier_id = frontier.id;
    let key_secret = [9; crypto::XCHACHA20_POLY1305_KEY_BYTES];
    let message = signed_content_message_fact(
        workspace_id,
        [44; 32],
        signer_id,
        &signer_private,
        frontier_id,
        key_secret,
        60_000,
        "runtime signed message",
    );
    let mut runtime = ProtocolRuntime::open_memory().expect("runtime");

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
        runtime
            .store()
            .table_rows(content_message::rows::CONTENT_MESSAGE_ROWS)
            .expect("content message rows")
            .is_empty(),
        "content rows wait until author context is available"
    );
    assert!(
        runtime
            .store()
            .table_rows(content_message::rows::OPENED_MESSAGE_ROWS)
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
    let declared = PROTOCOL
        .handlers
        .iter()
        .map(|handler| handler.runtime_field.to_string())
        .collect::<BTreeSet<_>>();
    let dispatched = runtime_dispatch_handler_routes();

    for required in [
        "purge_message_child",
        "purge_expired_message",
        "purge_below_retention_floor",
    ] {
        assert!(
            declared.contains(required),
            "{required} must be declared in the protocol registry"
        );
        assert!(
            dispatched.contains(required),
            "{required} must be included by HANDLER_ROUTES"
        );
    }

    let missing = declared
        .difference(&dispatched)
        .cloned()
        .collect::<Vec<_>>();
    let unexpected = dispatched
        .difference(&declared)
        .cloned()
        .collect::<Vec<_>>();

    assert!(
        missing.is_empty() && unexpected.is_empty(),
        "HANDLER_ROUTES must stay in lockstep with protocol handler registrations\nmissing from runtime dispatch: {missing:?}\nunexpected runtime dispatch handlers: {unexpected:?}"
    );
}

fn removal_frontier_fact(workspace_id: [u8; 32], owner_endpoint_id: [u8; 32]) -> Fact {
    let body = RemovalFrontierFact {
        workspace_id,
        owner_endpoint_id,
        created_at_ms: 1,
    };
    Fact::new(
        workspace_scope(workspace_id),
        1,
        encryption_layout::encode_removal_frontier(&body).expect("encode removal frontier"),
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
        encryption_layout::encode_local_key_secret(&LocalKeySecretFact {
            workspace_id,
            frontier_id,
            owner_endpoint_id,
            created_at_ms: 1,
            key_secret,
        })
        .expect("encode local key secret"),
    )
}

fn signed_content_message_fact(
    workspace_id: [u8; 32],
    author_user_id: [u8; 32],
    signer_id: [u8; 32],
    signer_private: &[u8; 32],
    frontier_id: [u8; 32],
    key_secret: [u8; crypto::XCHACHA20_POLY1305_KEY_BYTES],
    created_at_ms: u64,
    text: &str,
) -> Fact {
    let minute = created_at_ms / 60_000;
    let nonce = [7; content_message::fact::NONCE_BYTES];
    let plaintext = content_message::create::pad_plaintext(text.as_bytes()).expect("pad text");
    let ciphertext = crypto::xchacha20poly1305_encrypt(
        &key_secret,
        &content_message::create::associated_data(workspace_id, frontier_id, minute),
        &nonce,
        &plaintext,
    )
    .expect("encrypt message");
    let body = content_message::fact::ContentMessageFact {
        workspace_id,
        created_at_ms,
        author_user_id,
        signer_id,
        frontier_id,
        local_history_node_secret_id: [0; 32],
        expires_at_minute: u64::MAX,
        disappearing_setting_id: [0; 32],
        minute,
        leaf_id: [4; 32],
        nonce,
        ciphertext,
    };
    let payload = content_message::layout::encode_fact(&body).expect("encode content message");
    let bytes = signed_fact_create::sign_payload_bytes(signer_id, signer_private, payload)
        .expect("sign content message");
    Fact::new(workspace_scope(workspace_id), created_at_ms, bytes)
}

fn workspace_scope(workspace_id: [u8; 32]) -> FactScope {
    FactScope::Scoped {
        kind: ScopeKind::new("workspace").expect("valid workspace scope"),
        id: workspace_id,
    }
}

fn runtime_dispatch_handler_routes() -> BTreeSet<String> {
    let runtime_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocol/registry.rs");
    let source = std::fs::read_to_string(&runtime_path)
        .unwrap_or_else(|err| panic!("read {}: {err}", runtime_path.display()));
    let const_start = source
        .find("const HANDLER_ROUTES")
        .expect("HANDLER_ROUTES declaration");
    let start = source[const_start..]
        .find("&[")
        .map(|offset| const_start + offset)
        .expect("HANDLER_ROUTES body start");
    let end = source[start..]
        .find("];")
        .map(|offset| start + offset)
        .expect("HANDLER_ROUTES body end");
    let body = &source[start..end];

    let mut routes = BTreeSet::new();
    let mut rest = body;
    while let Some(index) = rest.find("name: \"") {
        let after_prefix = &rest[index + "name: \"".len()..];
        let field_len = after_prefix
            .chars()
            .take_while(|ch| *ch != '"')
            .map(char::len_utf8)
            .sum::<usize>();
        if field_len > 0 {
            routes.insert(after_prefix[..field_len].to_string());
        }
        rest = &after_prefix[field_len..];
    }
    routes
}
