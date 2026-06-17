//! Invite link creation and parsing.
//!
//! Invite links are out-of-band carriers. The durable protocol state is still
//! facts:
//!
//! - creator side: a local invite-secret fact and, for workspace invites, a
//!   shared user-invite fact;
//! - acceptor side: retained invite-accepted provenance containing the accepted
//!   link bootstrap context, plus any proposed user/device facts. The live
//!   `maintain_connections` loop creates bootstrap request attempts later.
//!
//! This module does not write rows or run projection. It returns authored facts
//! that the runtime admits through the normal projection path.

use std::net::SocketAddr;
use std::str::FromStr;

use crate::core::command::AuthoredFacts;
use crate::core::crypto;
use crate::core::db::Db;
use crate::core::facts::FactId;
use crate::protocol::auth;
use crate::protocol::auth::signature::author::AuthoredFactEvidence;

const INVITE_PREFIX: &str = "topo://invite/";
const INVITE_VERSION: &str = "v6";
const INVITE_KIND: &str = "user";
const LABEL_INVITE_ID: &str = "INVITE_ID";
const LABEL_INVITE_PRIVKEY: &str = "INVITE_PRIVKEY";
const LABEL_WORKSPACE: &str = "WORKSPACE";
const LABEL_SCOPE: &str = "SCOPE";
const SCOPE_IDENTITY: &str = "identity";
const LABEL_USER_ID: &str = "USER_ID";
const LABEL_ENDPOINT_ROLE: &str = "ENDPOINT_ROLE";
const LABEL_ENDPOINT_ID: &str = "ENDPOINT_ID";
const LABEL_ADDRESS: &str = "ADDRESS";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteEndpointRole {
    Device,
    InviteServer,
}

impl InviteEndpointRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::InviteServer => "invite-server",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invite {
    pub endpoint: FactId,
    pub bootstrap_secret: [u8; 32],
    pub addr: SocketAddr,
    pub invite_fact_id: FactId,
    pub workspace_id: FactId,
    pub user_authority_fact_id: Option<FactId>,
    pub endpoint_role: InviteEndpointRole,
    pub identity_scope: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateInvite {
    pub created_at_ms: u64,
    pub workspace_id: Option<FactId>,
    pub public_addr: SocketAddr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateInviteReceipt {
    pub link: String,
    pub invite_fact_id: FactId,
    pub invite_secret_id: FactId,
    pub workspace_id: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateDeviceLink {
    pub created_at_ms: u64,
    pub workspace_id: FactId,
    pub public_addr: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateInviteServer {
    pub created_at_ms: u64,
    pub workspace_id: FactId,
    pub public_addr: SocketAddr,
}

pub fn create(
    store: &Db,
    input: CreateInvite,
) -> Result<AuthoredFacts<CreateInviteReceipt>, String> {
    let endpoint_output = auth::endpoint::api::local_or_create(store, input.created_at_ms)?;
    let local = endpoint_output.receipt.endpoint;
    let invite_private_key = crypto::random_ed25519_private_key();

    let (invite_fact_id, workspace_id, mut facts) = match input.workspace_id {
        Some(workspace_id) => {
            let authority = local_admin_id(store, workspace_id, local.signing_public_key)?;
            let user_invite = auth::user_invite::api::create_with_secret(
                auth::user_invite::api::CreateUserInviteWithSecret {
                    created_at_ms: input.created_at_ms.saturating_add(1),
                    workspace_id,
                    authority_fact_id: authority.admin_id,
                    signer_id: authority.signer_id,
                    invite_private_key,
                    signer_private_key: local.signing_secret,
                },
            )?;
            (
                user_invite.receipt.user_invite_id,
                workspace_id,
                user_invite.facts,
            )
        }
        None => (
            crypto::random_bytes_32(),
            crypto::random_bytes_32(),
            Vec::new(),
        ),
    };

    let (_invite_secret, invite_secret_fact) = match input.workspace_id {
        Some(workspace_id) => super::author::scoped_secret_fact(
            invite_private_key,
            workspace_id,
            invite_fact_id,
            input.created_at_ms.saturating_add(2),
        )?,
        None => super::author::unscoped_secret_fact(
            invite_private_key,
            input.created_at_ms.saturating_add(2),
        )?,
    };
    facts.push(invite_secret_fact.clone());
    facts.splice(0..0, endpoint_output.facts);

    let link = format_invite(Invite {
        endpoint: local.endpoint,
        bootstrap_secret: invite_private_key,
        addr: input.public_addr,
        invite_fact_id,
        workspace_id,
        user_authority_fact_id: None,
        endpoint_role: InviteEndpointRole::Device,
        identity_scope: input.workspace_id.is_some(),
    });

    Ok(AuthoredFacts::new(CreateInviteReceipt {
        link,
        invite_fact_id,
        invite_secret_id: invite_secret_fact.id,
        workspace_id,
    })
    .with_facts(facts))
}

pub fn create_device_link(
    store: &Db,
    input: CreateDeviceLink,
) -> Result<AuthoredFacts<CreateInviteReceipt>, String> {
    let endpoint_output = auth::endpoint::api::local_or_create(store, input.created_at_ms)?;
    let local = endpoint_output.receipt.endpoint;
    let membership = auth::workspace::queries::local_membership(store, input.workspace_id)?
        .ok_or_else(|| "local endpoint has not joined this workspace".to_string())?;
    if membership.signing_public_key != local.signing_public_key {
        return Err("local endpoint signing key does not match workspace membership".to_string());
    }
    if membership.endpoint_role != auth::endpoint_shared::fact::EndpointRole::Device {
        return Err("local endpoint role cannot create device links".to_string());
    }
    let user = auth::user::queries::users_in_workspace(store, input.workspace_id)?
        .into_iter()
        .find(|user| user.user_id == membership.user_authority_fact_id)
        .ok_or_else(|| "local endpoint user is missing".to_string())?;

    let invite_private_key = crypto::random_ed25519_private_key();
    let device_invite_fact = auth::device_invite::author::authored_device_invite_fact(
        input.created_at_ms.saturating_add(1),
        input.workspace_id,
        user.user_id,
        None,
        crypto::ed25519_public_key(&invite_private_key),
        membership.endpoint_shared_id,
        local.signing_secret,
    )?;
    let device_invite_signature = auth::signature::author::sign_fact(
        input.workspace_id,
        &device_invite_fact,
        &local.signing_secret,
        input.created_at_ms.saturating_add(1),
    )?;
    let (_invite_secret, invite_secret_fact) = super::author::scoped_secret_fact(
        invite_private_key,
        input.workspace_id,
        device_invite_fact.id,
        input.created_at_ms.saturating_add(2),
    )?;
    let mut facts = endpoint_output.facts;
    facts.push(device_invite_fact.clone());
    facts.push(device_invite_signature);
    facts.push(invite_secret_fact.clone());

    let link = format_invite(Invite {
        endpoint: local.endpoint,
        bootstrap_secret: invite_private_key,
        addr: input.public_addr,
        invite_fact_id: device_invite_fact.id,
        workspace_id: input.workspace_id,
        user_authority_fact_id: Some(user.user_id),
        endpoint_role: InviteEndpointRole::Device,
        identity_scope: true,
    });

    Ok(AuthoredFacts::new(CreateInviteReceipt {
        link,
        invite_fact_id: device_invite_fact.id,
        invite_secret_id: invite_secret_fact.id,
        workspace_id: input.workspace_id,
    })
    .with_facts(facts))
}

pub fn create_invite_server(
    store: &Db,
    input: CreateInviteServer,
) -> Result<AuthoredFacts<CreateInviteReceipt>, String> {
    let endpoint_output = auth::endpoint::api::local_or_create(store, input.created_at_ms)?;
    let local = endpoint_output.receipt.endpoint;
    let authority = local_admin_id(store, input.workspace_id, local.signing_public_key)?;
    let invite_private_key = crypto::random_ed25519_private_key();
    let invite_server_fact = auth::invite_server::author::authored_invite_server_fact(
        input.created_at_ms.saturating_add(1),
        crypto::ed25519_public_key(&invite_private_key),
        input.workspace_id,
        authority.admin_id,
        authority.signer_id,
        local.signing_public_key,
    )?;
    let invite_server_signature = auth::signature::author::sign_fact(
        input.workspace_id,
        &invite_server_fact,
        &local.signing_secret,
        input.created_at_ms.saturating_add(1),
    )?;
    let (_invite_secret, invite_secret_fact) = super::author::scoped_secret_fact(
        invite_private_key,
        input.workspace_id,
        invite_server_fact.id,
        input.created_at_ms.saturating_add(2),
    )?;
    let mut facts = endpoint_output.facts;
    facts.push(invite_server_fact.clone());
    facts.push(invite_server_signature);
    facts.push(invite_secret_fact.clone());

    let link = format_invite(Invite {
        endpoint: local.endpoint,
        bootstrap_secret: invite_private_key,
        addr: input.public_addr,
        invite_fact_id: invite_server_fact.id,
        workspace_id: input.workspace_id,
        user_authority_fact_id: None,
        endpoint_role: InviteEndpointRole::InviteServer,
        identity_scope: true,
    });

    Ok(AuthoredFacts::new(CreateInviteReceipt {
        link,
        invite_fact_id: invite_server_fact.id,
        invite_secret_id: invite_secret_fact.id,
        workspace_id: input.workspace_id,
    })
    .with_facts(facts))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptInvite {
    pub created_at_ms: u64,
    pub invite: Invite,
    pub username: Option<String>,
    pub device_name: Option<String>,
    pub from_listen_addr: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptInviteReceipt {
    pub connected_addr: SocketAddr,
    pub workspace_id: Option<FactId>,
    pub user_id: Option<FactId>,
    pub endpoint_shared_id: Option<FactId>,
    pub endpoint_role: Option<InviteEndpointRole>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptDeviceLink {
    pub created_at_ms: u64,
    pub invite: Invite,
    pub device_name: String,
    pub from_listen_addr: Option<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptInviteServer {
    pub created_at_ms: u64,
    pub invite: Invite,
    pub device_name: String,
    pub from_listen_addr: Option<SocketAddr>,
}

pub fn accept(
    store: &Db,
    input: AcceptInvite,
) -> Result<AuthoredFacts<AcceptInviteReceipt>, String> {
    let endpoint_output = auth::endpoint::api::local_or_create(store, input.created_at_ms)?;
    let local = endpoint_output.receipt.endpoint;
    if input.invite.identity_scope {
        reject_duplicate_join(store, local.endpoint, input.invite.workspace_id)?;
    }

    let mut facts = endpoint_output.facts;

    let mut user_id = None;
    if input.invite.identity_scope {
        if input.invite.endpoint_role != InviteEndpointRole::Device {
            return Err("accept requires a user invite".to_string());
        }
        let username = input
            .username
            .ok_or_else(|| "accept requires --username for workspace invites".to_string())?;
        let device_name = input
            .device_name
            .ok_or_else(|| "accept requires --devicename for workspace invites".to_string())?;
        if device_name.trim().is_empty() {
            return Err("device name must not be empty".to_string());
        }

        let user =
            auth::user::api::create_with_authority(auth::user::api::CreateUserWithAuthority {
                created_at_ms: input.created_at_ms.saturating_add(4),
                workspace_id: input.invite.workspace_id,
                signer_id: input.invite.invite_fact_id,
                signer_private_key: input.invite.bootstrap_secret,
                username,
            })?;
        user_id = Some(user.receipt.user_id);
        facts.extend(user.facts);

        let device_invite = workspace_accept_device_invite_fact(
            input.created_at_ms.saturating_add(5),
            input.invite.workspace_id,
            user.receipt.user_id,
            input.invite.invite_fact_id,
            input.invite.bootstrap_secret,
        )?;

        let endpoint_shared = endpoint_shared_fact(EndpointSharedFactInput {
            created_at_ms: input.created_at_ms.saturating_add(6),
            workspace_id: input.invite.workspace_id,
            user_id: user.receipt.user_id,
            endpoint_id: local.endpoint,
            signing_public_key: local.signing_public_key,
            endpoint_role: auth::endpoint_shared::fact::EndpointRole::Device,
            device_name: &device_name,
            signer_id: device_invite.fact.id,
            signer_private_key: input.invite.bootstrap_secret,
        })?;
        facts.extend(device_invite.into_facts());
        facts.extend(endpoint_shared.into_facts());
    }
    let accepted = auth::invite_accepted::api::accept(auth::invite_accepted::api::AcceptInvite {
        created_at_ms: input
            .created_at_ms
            .saturating_add(if input.invite.identity_scope { 7 } else { 1 }),
        accepted_endpoint_id: local.endpoint,
        bootstrap_secret: input.invite.bootstrap_secret,
        bootstrap_endpoint_id: input.invite.endpoint,
        bootstrap_addr: input.invite.addr,
        workspace_id: input.invite.workspace_id,
        invite_fact_id: input.invite.invite_fact_id,
        user_authority_fact_id: input.invite.user_authority_fact_id,
        endpoint_role: endpoint_role_for_shared(input.invite.endpoint_role),
        identity_scope: input.invite.identity_scope,
    })?;
    facts.extend(accepted.facts);

    Ok(AuthoredFacts::new(AcceptInviteReceipt {
        connected_addr: input.invite.addr,
        workspace_id: input
            .invite
            .identity_scope
            .then_some(input.invite.workspace_id),
        user_id,
        endpoint_shared_id: None,
        endpoint_role: None,
    })
    .with_facts(facts))
}

fn workspace_accept_device_invite_fact(
    created_at_ms: u64,
    workspace_id: FactId,
    user_id: FactId,
    user_invite_fact_id: FactId,
    bootstrap_secret: [u8; 32],
) -> Result<AuthoredFactEvidence, String> {
    let fact = auth::device_invite::author::authored_device_invite_fact(
        created_at_ms,
        workspace_id,
        user_id,
        Some(user_invite_fact_id),
        crypto::ed25519_public_key(&bootstrap_secret),
        user_id,
        bootstrap_secret,
    )?;
    let signature =
        auth::signature::author::sign_fact(workspace_id, &fact, &bootstrap_secret, created_at_ms)?;
    Ok(AuthoredFactEvidence { fact, signature })
}

fn endpoint_role_for_shared(role: InviteEndpointRole) -> auth::endpoint_shared::fact::EndpointRole {
    match role {
        InviteEndpointRole::Device => auth::endpoint_shared::fact::EndpointRole::Device,
        InviteEndpointRole::InviteServer => auth::endpoint_shared::fact::EndpointRole::InviteServer,
    }
}

pub fn accept_device_link(
    store: &Db,
    input: AcceptDeviceLink,
) -> Result<AuthoredFacts<AcceptInviteReceipt>, String> {
    if !input.invite.identity_scope {
        return Err("accept-link requires a workspace-scoped link".to_string());
    }
    if input.device_name.trim().is_empty() {
        return Err("device name must not be empty".to_string());
    }
    let user_id = input
        .invite
        .user_authority_fact_id
        .ok_or_else(|| "accept-link requires a USER_ID invite part".to_string())?;
    let endpoint_output = auth::endpoint::api::local_or_create(store, input.created_at_ms)?;
    let local = endpoint_output.receipt.endpoint;
    reject_duplicate_join(store, local.endpoint, input.invite.workspace_id)?;

    let endpoint_shared = endpoint_shared_fact(EndpointSharedFactInput {
        created_at_ms: input.created_at_ms.saturating_add(4),
        workspace_id: input.invite.workspace_id,
        user_id,
        endpoint_id: local.endpoint,
        signing_public_key: local.signing_public_key,
        endpoint_role: auth::endpoint_shared::fact::EndpointRole::Device,
        device_name: &input.device_name,
        signer_id: input.invite.invite_fact_id,
        signer_private_key: input.invite.bootstrap_secret,
    })?;
    let accepted = auth::invite_accepted::api::accept(auth::invite_accepted::api::AcceptInvite {
        created_at_ms: input.created_at_ms.saturating_add(5),
        accepted_endpoint_id: local.endpoint,
        bootstrap_secret: input.invite.bootstrap_secret,
        bootstrap_endpoint_id: input.invite.endpoint,
        bootstrap_addr: input.invite.addr,
        workspace_id: input.invite.workspace_id,
        invite_fact_id: input.invite.invite_fact_id,
        user_authority_fact_id: input.invite.user_authority_fact_id,
        endpoint_role: endpoint_role_for_shared(input.invite.endpoint_role),
        identity_scope: true,
    })?;
    let mut facts = endpoint_output.facts;
    facts.extend(endpoint_shared.clone().into_facts());
    facts.extend(accepted.facts);

    Ok(AuthoredFacts::new(AcceptInviteReceipt {
        connected_addr: input.invite.addr,
        workspace_id: Some(input.invite.workspace_id),
        user_id: Some(user_id),
        endpoint_shared_id: Some(endpoint_shared.fact.id),
        endpoint_role: Some(InviteEndpointRole::Device),
    })
    .with_facts(facts))
}

pub fn accept_invite_server(
    store: &Db,
    input: AcceptInviteServer,
) -> Result<AuthoredFacts<AcceptInviteReceipt>, String> {
    if !input.invite.identity_scope
        || input.invite.endpoint_role != InviteEndpointRole::InviteServer
    {
        return Err("accept-invite-server requires an invite-server identity invite".to_string());
    }
    if input.invite.user_authority_fact_id.is_some() {
        return Err("invite-server invite must not carry USER_ID".to_string());
    }
    if input.device_name.trim().is_empty() {
        return Err("device name must not be empty".to_string());
    }
    let endpoint_output = auth::endpoint::api::local_or_create(store, input.created_at_ms)?;
    let local = endpoint_output.receipt.endpoint;
    reject_duplicate_join(store, local.endpoint, input.invite.workspace_id)?;

    let endpoint_shared = endpoint_shared_fact(EndpointSharedFactInput {
        created_at_ms: input.created_at_ms.saturating_add(4),
        workspace_id: input.invite.workspace_id,
        user_id: input.invite.invite_fact_id,
        endpoint_id: local.endpoint,
        signing_public_key: local.signing_public_key,
        endpoint_role: auth::endpoint_shared::fact::EndpointRole::InviteServer,
        device_name: &input.device_name,
        signer_id: input.invite.invite_fact_id,
        signer_private_key: input.invite.bootstrap_secret,
    })?;
    let accepted = auth::invite_accepted::api::accept(auth::invite_accepted::api::AcceptInvite {
        created_at_ms: input.created_at_ms.saturating_add(5),
        accepted_endpoint_id: local.endpoint,
        bootstrap_secret: input.invite.bootstrap_secret,
        bootstrap_endpoint_id: input.invite.endpoint,
        bootstrap_addr: input.invite.addr,
        workspace_id: input.invite.workspace_id,
        invite_fact_id: input.invite.invite_fact_id,
        user_authority_fact_id: input.invite.user_authority_fact_id,
        endpoint_role: endpoint_role_for_shared(input.invite.endpoint_role),
        identity_scope: true,
    })?;
    let mut facts = endpoint_output.facts;
    facts.extend(endpoint_shared.clone().into_facts());
    facts.extend(accepted.facts);

    Ok(AuthoredFacts::new(AcceptInviteReceipt {
        connected_addr: input.invite.addr,
        workspace_id: Some(input.invite.workspace_id),
        user_id: None,
        endpoint_shared_id: Some(endpoint_shared.fact.id),
        endpoint_role: Some(InviteEndpointRole::InviteServer),
    })
    .with_facts(facts))
}

struct EndpointSharedFactInput<'a> {
    created_at_ms: u64,
    workspace_id: FactId,
    user_id: FactId,
    endpoint_id: FactId,
    signing_public_key: [u8; 32],
    endpoint_role: auth::endpoint_shared::fact::EndpointRole,
    device_name: &'a str,
    signer_id: FactId,
    signer_private_key: [u8; 32],
}

fn endpoint_shared_fact(
    input: EndpointSharedFactInput<'_>,
) -> Result<AuthoredFactEvidence, String> {
    let fact = auth::endpoint_shared::author::authored_endpoint_shared_fact(
        input.created_at_ms,
        input.workspace_id,
        input.user_id,
        input.endpoint_id,
        input.signing_public_key,
        input.endpoint_role,
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

pub fn parse(value: &str) -> Result<Invite, String> {
    let body = value
        .strip_prefix(INVITE_PREFIX)
        .ok_or_else(|| "invite must start with topo://invite/".to_string())?;
    let mut parts = body.split('/');
    let version = parts
        .next()
        .ok_or_else(|| "invite is missing version".to_string())?;
    if version != INVITE_VERSION {
        return Err(format!("unsupported invite version {version}"));
    }
    let kind = parts
        .next()
        .ok_or_else(|| "invite is missing kind".to_string())?;
    if kind != INVITE_KIND {
        return Err(format!("unsupported invite kind {kind}"));
    }

    let mut endpoint = None;
    let mut bootstrap_secret = None;
    let mut addr = None;
    let mut invite_fact_id = None;
    let mut workspace_id = None;
    let mut user_authority_fact_id = None;
    let mut endpoint_role = None;
    let mut identity_scope = false;

    for part in parts {
        let (label, value) = part
            .split_once('.')
            .ok_or_else(|| format!("invite part `{part}` is missing label"))?;
        match label {
            LABEL_INVITE_ID => replace_once(&mut invite_fact_id, decode_hex_32(value)?, label)?,
            LABEL_INVITE_PRIVKEY => {
                replace_once(&mut bootstrap_secret, decode_hex_32(value)?, label)?
            }
            LABEL_WORKSPACE => replace_once(&mut workspace_id, decode_hex_32(value)?, label)?,
            LABEL_SCOPE => {
                if identity_scope {
                    return Err("invite has duplicate SCOPE".to_string());
                }
                if value != SCOPE_IDENTITY {
                    return Err(format!("unsupported invite scope {value}"));
                }
                identity_scope = true;
            }
            LABEL_USER_ID => {
                replace_once(&mut user_authority_fact_id, decode_hex_32(value)?, label)?
            }
            LABEL_ENDPOINT_ROLE => {
                replace_once(&mut endpoint_role, decode_endpoint_role(value)?, label)?
            }
            LABEL_ENDPOINT_ID => replace_once(&mut endpoint, decode_hex_32(value)?, label)?,
            LABEL_ADDRESS => replace_once(&mut addr, decode_address(value)?, label)?,
            other => return Err(format!("unknown invite part `{other}`")),
        }
    }

    Ok(Invite {
        endpoint: endpoint.ok_or_else(|| "invite is missing ENDPOINT_ID".to_string())?,
        bootstrap_secret: bootstrap_secret
            .ok_or_else(|| "invite is missing INVITE_PRIVKEY".to_string())?,
        addr: addr.ok_or_else(|| "invite is missing ADDRESS".to_string())?,
        invite_fact_id: invite_fact_id.ok_or_else(|| "invite is missing INVITE_ID".to_string())?,
        workspace_id: workspace_id.ok_or_else(|| "invite is missing WORKSPACE".to_string())?,
        user_authority_fact_id,
        endpoint_role: endpoint_role.unwrap_or(InviteEndpointRole::Device),
        identity_scope,
    })
}

pub fn format_invite(invite: Invite) -> String {
    let mut parts = vec![
        format!("{INVITE_PREFIX}{INVITE_VERSION}/{INVITE_KIND}"),
        format!("{LABEL_INVITE_ID}.{}", encode_hex(&invite.invite_fact_id)),
        format!(
            "{LABEL_INVITE_PRIVKEY}.{}",
            encode_hex(&invite.bootstrap_secret)
        ),
        format!("{LABEL_WORKSPACE}.{}", encode_hex(&invite.workspace_id)),
    ];
    if invite.identity_scope {
        parts.push(format!("{LABEL_SCOPE}.{SCOPE_IDENTITY}"));
        parts.push(format!(
            "{LABEL_ENDPOINT_ROLE}.{}",
            invite.endpoint_role.as_str()
        ));
    }
    if let Some(user_id) = invite.user_authority_fact_id {
        parts.push(format!("{LABEL_USER_ID}.{}", encode_hex(&user_id)));
    }
    parts.push(format!(
        "{LABEL_ENDPOINT_ID}.{}",
        encode_hex(&invite.endpoint)
    ));
    parts.push(format!("{LABEL_ADDRESS}.{}", encode_address(invite.addr)));
    parts.join("/")
}

struct LocalAdminAuthority {
    admin_id: FactId,
    signer_id: FactId,
}

fn local_admin_id(
    store: &Db,
    workspace_id: FactId,
    signing_public_key: [u8; 32],
) -> Result<LocalAdminAuthority, String> {
    let membership = auth::workspace::queries::local_membership(store, workspace_id)?
        .ok_or_else(|| "local endpoint has not joined this workspace".to_string())?;
    if membership.signing_public_key != signing_public_key {
        return Err("local endpoint signing key does not match workspace membership".to_string());
    }

    auth::admin::queries::admin_rows_in_workspace(store, workspace_id)?
        .into_iter()
        .find(|admin| admin.user_fact_id == membership.user_authority_fact_id)
        .map(|admin| LocalAdminAuthority {
            admin_id: admin.admin_id,
            signer_id: membership.endpoint_shared_id,
        })
        .ok_or_else(|| "local user is not an admin in this workspace".to_string())
}

fn reject_duplicate_join(
    store: &Db,
    endpoint_id: FactId,
    workspace_id: FactId,
) -> Result<(), String> {
    if auth::invite_accepted::queries::accepted_endpoint_in_workspace(
        store,
        endpoint_id,
        workspace_id,
    )? {
        return Err("endpoint is already joined to workspace".to_string());
    }
    Ok(())
}

fn replace_once<T: Copy>(slot: &mut Option<T>, value: T, label: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        Err(format!("invite has duplicate {label}"))
    } else {
        Ok(())
    }
}

fn decode_endpoint_role(value: &str) -> Result<InviteEndpointRole, String> {
    match value {
        "device" => Ok(InviteEndpointRole::Device),
        "invite-server" => Ok(InviteEndpointRole::InviteServer),
        other => Err(format!("unsupported endpoint role {other}")),
    }
}

fn encode_address(addr: SocketAddr) -> String {
    format!("{}_{}", addr.ip(), addr.port())
}

fn decode_address(value: &str) -> Result<SocketAddr, String> {
    if let Ok(addr) = SocketAddr::from_str(value) {
        return Ok(addr);
    }
    let (host, port) = value
        .rsplit_once('_')
        .ok_or_else(|| "invite ADDRESS must include a port".to_string())?;
    let port = u16::from_str(port).map_err(|_| "invite ADDRESS port is invalid".to_string())?;
    let candidate = if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    candidate
        .parse()
        .map_err(|_| "invite ADDRESS is invalid".to_string())
}

pub fn encode_hex(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}

pub fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("invite hex field must be 64 hex characters".to_string());
    }
    let mut out = [0; 32];
    let bytes = value.as_bytes();
    for idx in 0..32 {
        out[idx] = (hex_value(bytes[idx * 2])? << 4) | hex_value(bytes[idx * 2 + 1])?;
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invite hex field is not hex".to_string()),
    }
}
