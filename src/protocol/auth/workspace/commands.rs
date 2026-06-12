//! Command-facing workspace workflows.
//!
//! Commands receive stable context and compose deterministic constructors. They
//! do not project, write rows, or call intent handlers.

use crate::core::command_context::{CommandContext, CommandOutput};
use crate::core::crypto::{self, Ed25519PublicKey};
use crate::core::facts::{Fact, FactId};
use crate::core::pipeline::ProjectionContext;
use crate::core::store::Store;
use crate::protocol::auth;
use crate::protocol::auth::signature::author::AuthoredFactEvidence;
use crate::protocol::auth::workspace::author;
use crate::protocol::content;
use crate::protocol::content::retention_policy::fact::SCOPE_KIND_WORKSPACE;

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
    let workspace_private_key = crypto::random_ed25519_private_key();
    let workspace = author::create_workspace(created_at_ms, workspace_private_key, name)?;
    let workspace_signature = auth::signature::author::sign_fact(
        workspace.id,
        &workspace,
        &workspace_private_key,
        created_at_ms,
    )?;
    authenticate_workspace_fact(&workspace)?;
    let workspace_id = workspace.id;

    let user_invite = user_invite_fact(
        created_at_ms + 1,
        workspace_id,
        user_public,
        workspace_private_key,
    )?;
    let accepted =
        auth::invite_accepted::commands::accept(auth::invite_accepted::commands::AcceptInvite {
            created_at_ms: created_at_ms + 2,
            accepted_endpoint_id: endpoint.endpoint,
            bootstrap_secret: endpoint.signing_secret,
            bootstrap_endpoint_id: endpoint.endpoint,
            bootstrap_addr: "127.0.0.1:0".parse().expect("static bootstrap addr parses"),
            workspace_id,
            invite_fact_id: user_invite.fact.id,
            user_authority_fact_id: None,
            endpoint_role: auth::endpoint_shared::fact::EndpointRole::Device,
            identity_scope: true,
        })?;
    let user = user_fact(
        created_at_ms + 4,
        workspace_id,
        user_invite.fact.id,
        endpoint.signing_secret,
        identity.username,
    )?;
    let bootstrap_admin = bootstrap_admin_fact(
        created_at_ms + 5,
        workspace_id,
        user.fact.id,
        user_public,
        workspace_private_key,
    )?;
    let device_invite = device_invite_fact(
        created_at_ms + 6,
        workspace_id,
        user.fact.id,
        user_invite.fact.id,
        user_public,
        endpoint.signing_secret,
    )?;
    let endpoint_shared = endpoint_shared_fact(EndpointSharedFactInput {
        created_at_ms: created_at_ms + 7,
        workspace_id,
        user_id: user.fact.id,
        signing_public_key: user_public,
        device_name: identity.device_name,
        signer_id: device_invite.fact.id,
        signer_private_key: endpoint.signing_secret,
        new_endpoint_fact: endpoint_output.effects.facts.first(),
        store: ctx.store(),
    })?;
    let user_id = user.fact.id;
    let mut facts = vec![workspace, workspace_signature];
    facts.extend(user_invite.into_facts());
    facts.extend(accepted.effects.facts);
    facts.extend(user.into_facts());
    facts.extend(bootstrap_admin.into_facts());
    facts.extend(device_invite.into_facts());
    facts.extend(endpoint_shared.into_facts());
    if identity.ttl_minutes != Some(0) {
        facts.extend(
            initial_retention_policy_fact(
                created_at_ms + 8,
                workspace_id,
                user_id,
                endpoint.endpoint,
                identity.ttl_minutes.unwrap_or(60),
                endpoint.signing_secret,
            )?
            .into_facts(),
        );
    }
    facts.extend(endpoint_output.effects.facts);
    Ok(CommandOutput::new(CreateWorkspaceReceipt {
        workspace_fact_id: workspace_id,
        created_at_ms,
    })
    .with_facts(facts))
}

fn authenticate_workspace_fact(fact: &Fact) -> Result<(), String> {
    let decoded = super::decode::decode_fact(fact.body())?;
    super::authenticate::authenticate(fact, decoded, &ProjectionContext::default()).map(|_| ())
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

fn endpoint_shared_fact(
    input: EndpointSharedFactInput<'_>,
) -> Result<AuthoredFactEvidence, String> {
    let endpoint_id = if let Some(endpoint_fact) = input.new_endpoint_fact {
        auth::endpoint::decode::decode_fact(&endpoint_fact.bytes)?.endpoint
    } else {
        let value = input
            .store
            .table_row(
                auth::endpoint::LOCAL_ENDPOINT_ROWS,
                auth::endpoint::LOCAL_KEY,
            )
            .map_err(|err| format!("load local endpoint: {err}"))?
            .ok_or_else(|| "local endpoint row is missing".to_string())?;
        id32(&value, "local endpoint")?
    };
    let fact = auth::endpoint_shared::author::authored_endpoint_shared_fact(
        input.created_at_ms,
        input.workspace_id,
        input.user_id,
        endpoint_id,
        input.signing_public_key,
        auth::endpoint_shared::fact::EndpointRole::Device,
        input.device_name,
        input.signer_id,
        input.signer_private_key,
    )?;
    let signature = auth::signature::author::sign_fact(
        input.workspace_id,
        &fact,
        &input.signer_private_key,
        input.created_at_ms,
    )?;
    Ok(AuthoredFactEvidence { fact, signature })
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
) -> Result<AuthoredFactEvidence, String> {
    let fact = auth::user_invite::author::authored_user_invite_fact(
        created_at_ms,
        public_key,
        workspace_id,
        workspace_id,
        workspace_id,
        signer_private_key,
    )?;
    let signature = auth::signature::author::sign_fact(
        workspace_id,
        &fact,
        &signer_private_key,
        created_at_ms,
    )?;
    Ok(AuthoredFactEvidence { fact, signature })
}

fn user_fact(
    created_at_ms: u64,
    workspace_id: FactId,
    signer_id: FactId,
    signer_private_key: [u8; 32],
    username: &str,
) -> Result<AuthoredFactEvidence, String> {
    let fact = auth::user::author::authored_user_fact(
        created_at_ms,
        workspace_id,
        crypto::ed25519_public_key(&signer_private_key),
        username,
        signer_id,
        signer_private_key,
    )?;
    let signature = auth::signature::author::sign_fact(
        workspace_id,
        &fact,
        &signer_private_key,
        created_at_ms,
    )?;
    Ok(AuthoredFactEvidence { fact, signature })
}

fn bootstrap_admin_fact(
    created_at_ms: u64,
    workspace_id: FactId,
    user_fact_id: FactId,
    public_key: Ed25519PublicKey,
    workspace_private_key: [u8; 32],
) -> Result<AuthoredFactEvidence, String> {
    let payload = auth::admin::fact::AdminFact {
        created_at_ms,
        workspace_id,
        public_key,
        authority_fact_id: workspace_id,
        user_fact_id,
        signer_id: workspace_id,
        signer_public_key: crypto::ed25519_public_key(&workspace_private_key),
    };
    let fact = auth::admin::author::authored_admin_fact(
        created_at_ms,
        workspace_id,
        workspace_private_key,
        payload,
    )?;
    let signature = auth::signature::author::sign_fact(
        workspace_id,
        &fact,
        &workspace_private_key,
        created_at_ms,
    )?;
    Ok(AuthoredFactEvidence { fact, signature })
}

fn device_invite_fact(
    created_at_ms: u64,
    workspace_id: FactId,
    user_authority_fact_id: FactId,
    user_invite_fact_id: FactId,
    public_key: Ed25519PublicKey,
    signer_private_key: [u8; 32],
) -> Result<AuthoredFactEvidence, String> {
    let fact = auth::device_invite::author::authored_device_invite_fact(
        created_at_ms,
        workspace_id,
        user_authority_fact_id,
        Some(user_invite_fact_id),
        public_key,
        user_authority_fact_id,
        signer_private_key,
    )?;
    let signature = auth::signature::author::sign_fact(
        workspace_id,
        &fact,
        &signer_private_key,
        created_at_ms,
    )?;
    Ok(AuthoredFactEvidence { fact, signature })
}

fn initial_retention_policy_fact(
    created_at_ms: u64,
    workspace_id: FactId,
    author_user_id: FactId,
    signer_endpoint_id: FactId,
    ttl_minutes: u32,
    signer_private_key: [u8; 32],
) -> Result<AuthoredFactEvidence, String> {
    let fact = content::retention_policy::author::authored_retention_policy_fact(
        workspace_id,
        None,
        ttl_minutes,
        0,
        SCOPE_KIND_WORKSPACE,
        workspace_id,
        author_user_id,
        signer_endpoint_id,
        created_at_ms,
        signer_private_key,
    )?;
    let signature = auth::signature::author::sign_fact(
        workspace_id,
        &fact,
        &signer_private_key,
        created_at_ms,
    )?;
    Ok(AuthoredFactEvidence { fact, signature })
}
