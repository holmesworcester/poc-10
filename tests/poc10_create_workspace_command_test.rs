//! Integration tests for the `create_workspace` command.

use std::cell::Cell;

use topo::core::command_context::{
    CommandClock, CommandContext, IdentityVault, LocalEncryptionCapability, LocalSigningCapability,
    WorkspaceId,
};
use topo::core::schema::CORE_SCHEMA_SOURCE;
use topo::core::store::Store;
use topo::protocol::auth::{
    admin, endpoint, invite_accepted,
    signature::project::{authenticate as signature_authenticate, decode as signature_decode},
    user, user_invite,
    workspace::commands::{create_workspace_with_identity, BootstrapIdentity},
    workspace::project::decode as workspace_decode,
};
use topo::protocol::registry::FACTS_SCHEMA_SOURCE;

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
fn create_workspace_emits_decodable_workspace_fact() {
    let store = Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
        .expect("store");
    let clock = FixedClock(Cell::new(60_000));
    let vault = EmptyVault;
    let ctx = CommandContext::new(&store, &clock, &vault);

    let output = create_workspace_with_identity(
        &ctx,
        "Research",
        BootstrapIdentity {
            username: "alice",
            device_name: "alice-laptop",
            ttl_minutes: Some(0),
        },
    )
    .expect("create_workspace");
    assert_eq!(output.receipt.created_at_ms, 60_000);

    let workspace_fact = output
        .facts
        .iter()
        .find(|fact| fact.id == output.receipt.workspace_fact_id)
        .expect("workspace fact emitted");
    let decoded = workspace_decode::decode_fact(&workspace_fact.bytes).expect("decode fact");
    let signature = output
        .facts
        .iter()
        .filter_map(|fact| signature_decode::decode_fact(&fact.bytes).ok())
        .find(|signature| signature.target_fact_id == workspace_fact.id)
        .expect("workspace signature evidence emitted");
    signature_authenticate::prove_signature_evidence(&signature).expect("workspace signature");
    assert_eq!(decoded.name, "Research");
    assert_eq!(decoded.created_at_ms, 60_000);
}

#[test]
fn create_workspace_authors_first_user_through_bootstrap_invite_and_admin_grant() {
    let store = Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
        .expect("store");
    let clock = FixedClock(Cell::new(70_000));
    let vault = EmptyVault;
    let ctx = CommandContext::new(&store, &clock, &vault);

    let output = create_workspace_with_identity(
        &ctx,
        "Research",
        BootstrapIdentity {
            username: "alice",
            device_name: "alice-laptop",
            ttl_minutes: Some(0),
        },
    )
    .expect("create_workspace");
    let workspace_id = output.receipt.workspace_fact_id;
    let workspace = workspace_decode::decode_fact(
        output
            .facts
            .iter()
            .find(|fact| fact.id == workspace_id)
            .expect("workspace fact")
            .body(),
    )
    .expect("decode workspace");

    let user_invite_fact = output
        .facts
        .iter()
        .find(|fact| fact.body().first() == Some(&user_invite::TYPE_USER_INVITE))
        .expect("user invite fact");
    let first_invite =
        user_invite::decode_fact_payload(user_invite_fact.body()).expect("decode user invite");
    assert_eq!(first_invite.workspace_id, workspace_id);
    assert_eq!(first_invite.authority_fact_id, workspace_id);
    assert_eq!(first_invite.signer_id, workspace_id);
    assert_eq!(first_invite.signer_public_key, workspace.public_key);

    let accepted_fact = output
        .facts
        .iter()
        .find(|fact| fact.body().first() == Some(&invite_accepted::TYPE_INVITE_ACCEPTED))
        .expect("invite_accepted fact");
    let accepted =
        invite_accepted::decode_fact_payload(accepted_fact.body()).expect("decode invite_accepted");
    assert_eq!(accepted.workspace_id, workspace_id);
    assert_eq!(accepted.invite_fact_id, user_invite_fact.id);

    let endpoint_fact = output
        .facts
        .iter()
        .find(|fact| fact.body().first() == Some(&endpoint::TYPE_LOCAL_ENDPOINT))
        .expect("endpoint fact");
    let local_endpoint =
        endpoint::decode_fact_payload(endpoint_fact.body()).expect("decode endpoint");
    assert_eq!(
        accepted.bootstrap_secret, local_endpoint.signing_secret,
        "creator acceptance should use the first user's endpoint signing secret"
    );
    assert_eq!(accepted.bootstrap_endpoint_id, local_endpoint.endpoint);
    assert_eq!(
        accepted.bootstrap_hash,
        topo::protocol::auth::invite::fact::bootstrap_secret_hash(&accepted.bootstrap_secret)
    );

    let user_fact = output
        .facts
        .iter()
        .find(|fact| fact.body().first() == Some(&user::TYPE_USER))
        .expect("user fact");
    let created_user = user::decode_fact_payload(user_fact.body()).expect("decode user");
    assert_eq!(created_user.workspace_id, workspace_id);
    assert_eq!(created_user.signer_id, user_invite_fact.id);
    assert_eq!(created_user.signer_public_key, first_invite.public_key);

    let admins = output
        .facts
        .iter()
        .filter(|fact| fact.body().first() == Some(&admin::TYPE_ADMIN))
        .map(|fact| admin::decode_fact_payload(fact.body()).expect("decode admin"))
        .collect::<Vec<_>>();
    assert_eq!(
        admins.len(),
        1,
        "creator bootstrap should emit one admin grant"
    );
    let bootstrap_admin = &admins[0];
    assert_eq!(bootstrap_admin.workspace_id, workspace_id);
    assert_eq!(bootstrap_admin.authority_fact_id, workspace_id);
    assert_eq!(bootstrap_admin.signer_id, workspace_id);
    assert_eq!(bootstrap_admin.signer_public_key, workspace.public_key);
    assert_eq!(bootstrap_admin.user_fact_id, user_fact.id);
    assert_eq!(bootstrap_admin.public_key, created_user.public_key);
}

#[test]
fn create_workspace_rejects_blank_or_oversize_name() {
    let store = Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
        .expect("store");
    let clock = FixedClock(Cell::new(0));
    let vault = EmptyVault;
    let ctx = CommandContext::new(&store, &clock, &vault);

    let identity = BootstrapIdentity {
        username: "alice",
        device_name: "alice-laptop",
        ttl_minutes: Some(0),
    };
    let err = create_workspace_with_identity(&ctx, "   ", identity.clone())
        .expect_err("blank name must reject");
    assert!(err.to_lowercase().contains("blank"), "{err}");

    let too_long = "a".repeat(200);
    let err = create_workspace_with_identity(&ctx, &too_long, identity)
        .expect_err("long name must reject");
    assert!(err.contains("exceeds"), "{err}");
}
