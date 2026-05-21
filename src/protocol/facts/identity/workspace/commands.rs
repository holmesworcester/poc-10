//! Command-facing workspace workflows.
//!
//! Commands receive stable context and compose deterministic constructors. They
//! do not project, write rows, or call intent handlers.

use crate::core::command_context::{CommandContext, CommandOutput};
use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::store::Store;
use crate::protocol::facts::encryption;
use crate::protocol::facts::identity;
use crate::protocol::facts::identity::workspace::create;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateWorkspaceReceipt {
    pub workspace_fact_id: FactId,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapIdentity<'a> {
    pub username: &'a str,
    pub device_name: &'a str,
    pub ttl_minutes: Option<u32>,
}

pub fn create_workspace(
    ctx: &CommandContext<'_>,
    public_key: Ed25519PublicKey,
    name: &str,
) -> Result<CommandOutput<CreateWorkspaceReceipt>, String> {
    let created_at_ms = ctx.next_timestamp();
    let fact = create::create_workspace(created_at_ms, public_key, name)?;
    let receipt = CreateWorkspaceReceipt {
        workspace_fact_id: fact.id,
        created_at_ms,
    };
    Ok(CommandOutput::new(receipt).with_facts(vec![fact]))
}

pub fn create_workspace_with_identity(
    ctx: &CommandContext<'_>,
    name: &str,
    identity: BootstrapIdentity<'_>,
) -> Result<CommandOutput<CreateWorkspaceReceipt>, String> {
    let created_at_ms = ctx.next_timestamp();
    let endpoint_output =
        identity::endpoint::commands::local_or_create(ctx.store(), created_at_ms + 4)?;
    let endpoint = endpoint_output.receipt.endpoint;
    let user_public = endpoint.signing_public_key;
    let workspace = create::create_workspace(created_at_ms, user_public, name)?;
    let workspace_id = workspace.id;

    let user_invite = user_invite_fact(
        created_at_ms + 1,
        workspace_id,
        user_public,
        endpoint.signing_secret,
    )?;
    let user = user_fact(
        created_at_ms + 2,
        workspace_id,
        user_invite.id,
        endpoint.signing_secret,
        identity.username,
    )?;
    let root_admin = root_admin_fact(
        created_at_ms + 3,
        workspace_id,
        user_public,
        endpoint.signing_secret,
    )?;
    let creator_admin = creator_admin_fact(
        created_at_ms + 4,
        workspace_id,
        user_public,
        root_admin.id,
        user.id,
        endpoint.signing_secret,
    )?;
    let device_invite = device_invite_fact(
        created_at_ms + 5,
        workspace_id,
        user.id,
        user_invite.id,
        user_public,
        endpoint.signing_secret,
    )?;
    let endpoint_shared = endpoint_shared_fact(
        created_at_ms + 6,
        workspace_id,
        user.id,
        user_public,
        identity.device_name,
        device_invite.id,
        endpoint.signing_secret,
        endpoint_output.effects.facts.first(),
        ctx.store(),
    )?;
    let mut facts = vec![
        workspace,
        user_invite,
        user,
        root_admin,
        creator_admin,
        device_invite,
        endpoint_shared,
    ];
    if identity.ttl_minutes != Some(0) {
        facts.push(initial_disappearing_setting_fact(
            created_at_ms + 7,
            workspace_id,
            identity.ttl_minutes.unwrap_or(60),
        )?);
    }
    facts.extend(endpoint_output.effects.facts);
    Ok(CommandOutput::new(CreateWorkspaceReceipt {
        workspace_fact_id: workspace_id,
        created_at_ms,
    })
    .with_facts(facts))
}

fn endpoint_shared_fact(
    created_at_ms: u64,
    workspace_id: FactId,
    user_id: FactId,
    signing_public_key: Ed25519PublicKey,
    device_name: &str,
    signer_id: FactId,
    signer_private_key: [u8; 32],
    new_endpoint_fact: Option<&Fact>,
    store: &Store,
) -> Result<Fact, String> {
    let endpoint_id = if let Some(endpoint_fact) = new_endpoint_fact {
        identity::endpoint::layout::decode_fact(&endpoint_fact.bytes)?.endpoint
    } else {
        let value = store
            .table_row(
                identity::endpoint::rows::LOCAL_ENDPOINT_ROWS,
                identity::endpoint::rows::LOCAL_KEY,
            )
            .map_err(|err| format!("load local endpoint: {err}"))?
            .ok_or_else(|| "local endpoint row is missing".to_string())?;
        id32(&value, "local endpoint")?
    };
    let payload = identity::endpoint_shared::fact::EndpointSharedFact {
        created_at_ms,
        workspace_id,
        user_authority_fact_id: user_id,
        endpoint_id,
        signing_public_key,
        endpoint_role: identity::endpoint_shared::fact::EndpointRole::Device,
        device_name: device_name.to_string(),
    };
    let bytes = crate::protocol::facts::identity::signed_fact::create::sign_payload_bytes(
        signer_id,
        &signer_private_key,
        identity::endpoint_shared::layout::encode_fact(&payload)?,
    )?;
    Ok(Fact::new(FactScope::Global, created_at_ms, bytes))
}

fn id32(value: &[u8], label: &str) -> Result<[u8; 32], String> {
    value
        .try_into()
        .map_err(|_| format!("{label} row must be 32 bytes"))
}

fn user_invite_fact(
    created_at_ms: u64,
    workspace_id: FactId,
    public_key: Ed25519PublicKey,
    signer_private_key: [u8; 32],
) -> Result<Fact, String> {
    identity::user_invite::commands::signed_user_invite_fact(
        identity::user_invite::commands::CreateUserInvite {
            created_at_ms,
            public_key,
            workspace_id,
            authority_fact_id: workspace_id,
        },
        workspace_id,
        signer_private_key,
    )
}

fn user_fact(
    created_at_ms: u64,
    workspace_id: FactId,
    signer_id: FactId,
    signer_private_key: [u8; 32],
    username: &str,
) -> Result<Fact, String> {
    identity::user::commands::signed_user_fact(
        &identity::user::commands::CreateSignedUser {
            created_at_ms,
            workspace_id,
            signer_id,
            signer_private_key,
            username: username.to_string(),
        },
        crate::core::crypto::ed25519_public_key(&signer_private_key),
    )
}

fn root_admin_fact(
    created_at_ms: u64,
    workspace_id: FactId,
    public_key: Ed25519PublicKey,
    signer_private_key: [u8; 32],
) -> Result<Fact, String> {
    let payload = identity::admin::fact::AdminFact {
        created_at_ms,
        workspace_id,
        public_key,
        authority_fact_id: workspace_id,
        user_fact_id: workspace_id,
    };
    identity::admin::commands::signed_admin_fact(
        created_at_ms,
        workspace_id,
        signer_private_key,
        payload,
    )
}

fn creator_admin_fact(
    created_at_ms: u64,
    workspace_id: FactId,
    public_key: Ed25519PublicKey,
    authority_fact_id: FactId,
    user_fact_id: FactId,
    signer_private_key: [u8; 32],
) -> Result<Fact, String> {
    let payload = identity::admin::fact::AdminFact {
        created_at_ms,
        workspace_id,
        public_key,
        authority_fact_id,
        user_fact_id,
    };
    identity::admin::commands::signed_admin_fact(
        created_at_ms,
        authority_fact_id,
        signer_private_key,
        payload,
    )
}

fn device_invite_fact(
    created_at_ms: u64,
    workspace_id: FactId,
    user_authority_fact_id: FactId,
    user_invite_fact_id: FactId,
    public_key: Ed25519PublicKey,
    signer_private_key: [u8; 32],
) -> Result<Fact, String> {
    let payload = identity::device_invite::fact::DeviceInviteFact {
        created_at_ms,
        workspace_id,
        user_authority_fact_id,
        user_invite_fact_id: Some(user_invite_fact_id),
        public_key,
    };
    let bytes = crate::protocol::facts::identity::signed_fact::create::sign_payload_bytes(
        user_authority_fact_id,
        &signer_private_key,
        identity::device_invite::layout::encode_fact(&payload)?,
    )?;
    Ok(Fact::new(FactScope::Global, created_at_ms, bytes))
}

fn initial_disappearing_setting_fact(
    created_at_ms: u64,
    workspace_id: FactId,
    ttl_minutes: u32,
) -> Result<Fact, String> {
    let payload =
        encryption::disappearing_messages_setting::fact::DisappearingMessagesSettingFact {
            workspace_id,
            supersedes_setting_id: None,
            ttl_minutes,
            retire_minute: 0,
            scope_kind: encryption::disappearing_messages_setting::fact::SCOPE_KIND_WORKSPACE,
            scope_id: workspace_id,
            author_user_id: workspace_id,
            created_at_ms,
        };
    Ok(Fact::new(
        FactScope::Global,
        created_at_ms,
        encryption::disappearing_messages_setting::layout::encode_fact(&payload)?,
    ))
}
