//! Command-facing workspace workflows.
//!
//! Commands receive stable context and compose deterministic constructors. They
//! do not project, write rows, or call intent handlers.

use crate::core::command_context::{CommandContext, CommandOutput};
use crate::core::crypto::{self, Ed25519PublicKey};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::store::Store;
use crate::protocol::auth;
use crate::protocol::auth::workspace::create;
use crate::protocol::content;

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
    let _ = (ctx, public_key, name);
    Err(
        "create_workspace now requires a local signing key; use the bootstrap identity form"
            .to_string(),
    )
}

pub fn create_workspace_with_identity(
    ctx: &CommandContext<'_>,
    name: &str,
    identity: BootstrapIdentity<'_>,
) -> Result<CommandOutput<CreateWorkspaceReceipt>, String> {
    let created_at_ms = ctx.next_timestamp();
    let endpoint_output =
        auth::endpoint::commands::local_or_create(ctx.store(), created_at_ms + 4)?;
    let endpoint = endpoint_output.receipt.endpoint;
    let user_public = endpoint.signing_public_key;
    let workspace = create::create_workspace(created_at_ms, endpoint.signing_secret, name)?;
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
    let endpoint_shared = endpoint_shared_fact(EndpointSharedFactInput {
        created_at_ms: created_at_ms + 6,
        workspace_id,
        user_id: user.id,
        signing_public_key: user_public,
        device_name: identity.device_name,
        signer_id: device_invite.id,
        signer_private_key: endpoint.signing_secret,
        new_endpoint_fact: endpoint_output.effects.facts.first(),
        store: ctx.store(),
    })?;
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
        facts.push(initial_retention_policy_fact(
            created_at_ms + 7,
            workspace_id,
            identity.ttl_minutes.unwrap_or(60),
            endpoint.signing_secret,
        )?);
    }
    facts.extend(endpoint_output.effects.facts);
    Ok(CommandOutput::new(CreateWorkspaceReceipt {
        workspace_fact_id: workspace_id,
        created_at_ms,
    })
    .with_facts(facts))
}

struct EndpointSharedFactInput<'a> {
    created_at_ms: u64,
    workspace_id: FactId,
    user_id: FactId,
    signing_public_key: Ed25519PublicKey,
    device_name: &'a str,
    signer_id: FactId,
    signer_private_key: [u8; 32],
    new_endpoint_fact: Option<&'a Fact>,
    store: &'a Store,
}

fn endpoint_shared_fact(input: EndpointSharedFactInput<'_>) -> Result<Fact, String> {
    let endpoint_id = if let Some(endpoint_fact) = input.new_endpoint_fact {
        auth::endpoint::layout::decode_fact(&endpoint_fact.bytes)?.endpoint
    } else {
        let value = input
            .store
            .table_row(
                auth::endpoint::rows::LOCAL_ENDPOINT_ROWS,
                auth::endpoint::rows::LOCAL_KEY,
            )
            .map_err(|err| format!("load local endpoint: {err}"))?
            .ok_or_else(|| "local endpoint row is missing".to_string())?;
        id32(&value, "local endpoint")?
    };
    let payload = auth::endpoint_shared::fact::EndpointSharedFact {
        created_at_ms: input.created_at_ms,
        workspace_id: input.workspace_id,
        user_authority_fact_id: input.user_id,
        endpoint_id,
        signing_public_key: input.signing_public_key,
        endpoint_role: auth::endpoint_shared::fact::EndpointRole::Device,
        device_name: auth::endpoint_shared::fact::EndpointDeviceName::new(input.device_name)
            .map_err(|err| format!("endpoint device name: {err}"))?,
        signer_id: input.signer_id,
        signer_public_key: crypto::ed25519_public_key(&input.signer_private_key),
        signature: [0; crypto::ED25519_SIGNATURE_BYTES],
    };
    let mut payload = payload;
    let (_, signature) = crypto::ed25519_sign_canonical(
        &input.signer_private_key,
        &auth::endpoint_shared::layout::signing_bytes(&payload)?,
    );
    payload.signature = signature;
    Ok(Fact::new(
        FactScope::Global,
        input.created_at_ms,
        auth::endpoint_shared::layout::encode_fact(&payload)?,
    ))
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
    auth::user_invite::commands::signed_user_invite_fact(
        auth::user_invite::commands::CreateUserInvite {
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
    auth::user::commands::signed_user_fact(
        &auth::user::commands::CreateSignedUser {
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
    let payload = auth::admin::fact::AdminFact {
        created_at_ms,
        workspace_id,
        public_key,
        authority_fact_id: workspace_id,
        user_fact_id: workspace_id,
        signer_id: workspace_id,
        signer_public_key: crypto::ed25519_public_key(&signer_private_key),
        signature: [0; crypto::ED25519_SIGNATURE_BYTES],
    };
    auth::admin::commands::signed_admin_fact(
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
    let payload = auth::admin::fact::AdminFact {
        created_at_ms,
        workspace_id,
        public_key,
        authority_fact_id,
        user_fact_id,
        signer_id: authority_fact_id,
        signer_public_key: crypto::ed25519_public_key(&signer_private_key),
        signature: [0; crypto::ED25519_SIGNATURE_BYTES],
    };
    auth::admin::commands::signed_admin_fact(
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
    let payload = auth::device_invite::fact::DeviceInviteFact {
        created_at_ms,
        workspace_id,
        user_authority_fact_id,
        user_invite_fact_id: Some(user_invite_fact_id),
        public_key,
        signer_id: user_authority_fact_id,
        signer_public_key: crypto::ed25519_public_key(&signer_private_key),
        signature: [0; crypto::ED25519_SIGNATURE_BYTES],
    };
    let mut payload = payload;
    let (_, signature) = crypto::ed25519_sign_canonical(
        &signer_private_key,
        &auth::device_invite::layout::signing_bytes(&payload)?,
    );
    payload.signature = signature;
    Ok(Fact::new(
        FactScope::Global,
        created_at_ms,
        auth::device_invite::layout::encode_fact(&payload)?,
    ))
}

fn initial_retention_policy_fact(
    created_at_ms: u64,
    workspace_id: FactId,
    ttl_minutes: u32,
    signer_private_key: [u8; 32],
) -> Result<Fact, String> {
    let signer_public_key = crypto::ed25519_public_key(&signer_private_key);
    let mut payload = content::retention_policy::fact::RetentionPolicyFact {
        workspace_id,
        supersedes_policy_id: None,
        ttl_minutes,
        retire_minute: 0,
        scope_kind: content::retention_policy::fact::SCOPE_KIND_WORKSPACE,
        scope_id: workspace_id,
        author_user_id: workspace_id,
        signer_id: workspace_id,
        signer_public_key,
        created_at_ms,
        signature: [0; crypto::ED25519_SIGNATURE_BYTES],
    };
    let (_, signature) = crypto::ed25519_sign_canonical(
        &signer_private_key,
        &content::retention_policy::layout::signing_bytes(&payload)?,
    );
    payload.signature = signature;
    Ok(Fact::new(
        FactScope::Global,
        created_at_ms,
        content::retention_policy::layout::encode_fact(&payload)?,
    ))
}
