//! Target runtime facade tests.

use std::{cell::Cell, collections::BTreeSet, path::Path};

use topo::core::command_context::{
    CommandClock, IdentityVault, LocalEncryptionCapability, LocalSigningCapability, WorkspaceId,
};
use topo::core::crypto;
use topo::core::facts::{Fact, FactScope, ScopeKind};
use topo::protocol::facts::content::sealed_message::{
    create::send_message, fact::SignerPubkeyFact, layout as sealed_layout, rows as sealed_rows,
};
use topo::protocol::facts::encryption::{
    fact::{LocalKeySecretFact, RemovalFrontierFact},
    layout as encryption_layout,
};
use topo::protocol::facts::identity::signed_fact::fact::LocalSignerSecretFact;
use topo::protocol::facts::identity::workspace::{
    commands::create_workspace, rows as workspace_rows,
};
use topo::protocol::intents::sync::share_fact_with_workspace::SHARE_FACT_WITH_WORKSPACE;
use topo::protocol::runtime::ProtocolRuntime;
use topo::protocol::PROTOCOL;

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

#[derive(Debug, Clone)]
struct SeededVault {
    signing: LocalSigningCapability,
    encryption: LocalEncryptionCapability,
}

impl IdentityVault for SeededVault {
    fn local_signing_capability(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<LocalSigningCapability, String> {
        if self.signing.fact.workspace_id == workspace_id {
            Ok(self.signing.clone())
        } else {
            Err("no signing capability for workspace".to_string())
        }
    }

    fn local_encryption_capability(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<LocalEncryptionCapability, String> {
        if self.encryption.fact.workspace_id == workspace_id {
            Ok(self.encryption.clone())
        } else {
            Err("no encryption capability for workspace".to_string())
        }
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
    let report = runtime
        .drain_projection_until_idle(4, 32)
        .expect("drain projection");

    assert_eq!(receipt.created_at_ms, 123_000);
    assert_eq!(report.projections, 1);
    assert_eq!(runtime.wake_loop().intents().len(), 1);
    assert_eq!(
        runtime.wake_loop().intents()[0].kind.as_str(),
        SHARE_FACT_WITH_WORKSPACE
    );

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
fn runtime_routes_signed_sealed_message_to_sealed_message_projector() {
    let workspace_id = [42; 32];
    let signer_id = [11; 32];
    let signer_private = [7; 32];
    let signer_public = crypto::ed25519_public_key(&signer_private);
    let frontier = removal_frontier_fact(workspace_id, [33; 32]);
    let frontier_id = frontier.id;
    let mut runtime = ProtocolRuntime::open_memory().expect("runtime");
    let clock = FixedClock(Cell::new(60_000));
    let vault = SeededVault {
        signing: LocalSigningCapability {
            fact: LocalSignerSecretFact {
                workspace_id,
                signer_id,
                public_key: signer_public,
                private_key: signer_private,
            },
        },
        encryption: LocalEncryptionCapability {
            fact: LocalKeySecretFact {
                workspace_id,
                frontier_id,
                owner_endpoint_id: [33; 32],
                created_at_ms: 1,
                key_secret: [9; crypto::XCHACHA20_POLY1305_KEY_BYTES],
            },
        },
    };
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        send_message(&ctx, workspace_id, "runtime signed message").expect("send message")
    };
    let message_id = output.receipt.message_fact_id;

    runtime
        .submit_command_output(output)
        .expect("submit signed message command output");
    runtime.submit_fact(signer_pubkey_fact(workspace_id, signer_id, signer_public));
    runtime.submit_fact(frontier);
    runtime.submit_fact(local_key_secret_fact(
        workspace_id,
        frontier_id,
        [33; 32],
        [9; crypto::XCHACHA20_POLY1305_KEY_BYTES],
    ));
    let report = runtime
        .drain_projection_until_idle(8, 64)
        .expect("drain signed message projection");

    assert!(report.projections >= 3);
    let rows = runtime
        .store()
        .table_rows(sealed_rows::SEALED_MESSAGE_ROWS)
        .expect("sealed message rows");
    assert_eq!(rows.len(), 1);
    let row =
        sealed_rows::decode_sealed_message_row(&rows[0].0, &rows[0].1).expect("decode sealed row");
    assert_eq!(row.message_id, message_id);
    assert_eq!(row.workspace_id, workspace_id);
    assert_eq!(row.signer_id, signer_id);
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
            "{required} must be declared in src/protocol.rs"
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
        "HANDLER_ROUTES must stay in lockstep with src/protocol.rs handlers\nmissing from runtime dispatch: {missing:?}\nunexpected runtime dispatch handlers: {unexpected:?}"
    );
}

fn signer_pubkey_fact(workspace_id: [u8; 32], signer_id: [u8; 32], public_key: [u8; 32]) -> Fact {
    Fact::new(
        workspace_scope(workspace_id),
        0,
        sealed_layout::encode_signer_pubkey(&SignerPubkeyFact {
            signer_id,
            public_key,
        })
        .expect("encode signer pubkey"),
    )
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

fn workspace_scope(workspace_id: [u8; 32]) -> FactScope {
    FactScope::Scoped {
        kind: ScopeKind::new("workspace").expect("valid workspace scope"),
        id: workspace_id,
    }
}

fn runtime_dispatch_handler_routes() -> BTreeSet<String> {
    let runtime_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocol/runtime.rs");
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
