//! Invite link creation and parsing.
//!
//! Invite links are out-of-band carriers. The durable protocol state is still
//! facts:
//!
//! - creator side: a local invite-secret fact and, for workspace invites, a
//!   shared user-invite fact;
//! - acceptor side: a scoped local invite-secret fact, invite-accepted
//!   provenance, a proposed user fact, and a connection request.
//!
//! This module does not write rows or run projection. It returns command output
//! that the runtime admits through the normal projection pipeline.

use std::net::SocketAddr;
use std::str::FromStr;

use crate::core::command_context::{CommandContext, CommandOutput};
use crate::core::crypto;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::store::Store;
use crate::protocol::facts::connection;
use crate::protocol::facts::identity;

use super::fact::InviteSecretFact;

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
    ctx: &CommandContext<'_>,
    input: CreateInvite,
) -> Result<CommandOutput<CreateInviteReceipt>, String> {
    let endpoint_output =
        identity::endpoint::commands::local_or_create(ctx.store(), input.created_at_ms)?;
    let local = endpoint_output.receipt.endpoint;
    let invite_private_key = crypto::random_ed25519_private_key();

    let (invite_fact_id, workspace_id, mut facts) = match input.workspace_id {
        Some(workspace_id) => {
            let authority = local_admin_id(ctx.store(), workspace_id, local.signing_public_key)?;
            let user_invite = identity::user_invite::commands::create_with_secret(
                identity::user_invite::commands::CreateUserInviteWithSecret {
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
                user_invite.effects.facts,
            )
        }
        None => (
            crypto::random_bytes_32(),
            crypto::random_bytes_32(),
            Vec::new(),
        ),
    };

    let invite_secret = match input.workspace_id {
        Some(workspace_id) => {
            InviteSecretFact::scoped(invite_private_key, workspace_id, invite_fact_id)
        }
        None => InviteSecretFact::new(invite_private_key),
    };
    let invite_secret_fact = Fact::new(
        FactScope::Local,
        input.created_at_ms.saturating_add(2),
        super::layout::encode_fact(&invite_secret)?,
    );
    facts.push(invite_secret_fact.clone());
    facts.splice(0..0, endpoint_output.effects.facts);

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

    Ok(CommandOutput::new(CreateInviteReceipt {
        link,
        invite_fact_id,
        invite_secret_id: invite_secret_fact.id,
        workspace_id,
    })
    .with_facts(facts))
}

pub fn create_device_link(
    ctx: &CommandContext<'_>,
    input: CreateDeviceLink,
) -> Result<CommandOutput<CreateInviteReceipt>, String> {
    let endpoint_output =
        identity::endpoint::commands::local_or_create(ctx.store(), input.created_at_ms)?;
    let local = endpoint_output.receipt.endpoint;
    let membership =
        identity::workspace::local_membership::local_membership(ctx.store(), input.workspace_id)?
            .ok_or_else(|| "local endpoint has not joined this workspace".to_string())?;
    if membership.signing_public_key != local.signing_public_key {
        return Err("local endpoint signing key does not match workspace membership".to_string());
    }
    if membership.endpoint_role != identity::endpoint_shared::fact::EndpointRole::Device {
        return Err("local endpoint role cannot create device links".to_string());
    }
    let user = identity::user::queries::users_in_workspace(ctx.store(), input.workspace_id)?
        .into_iter()
        .find(|user| user.user_id == membership.user_authority_fact_id)
        .ok_or_else(|| "local endpoint user is missing".to_string())?;

    let invite_private_key = crypto::random_ed25519_private_key();
    let device_invite = identity::device_invite::fact::DeviceInviteFact {
        created_at_ms: input.created_at_ms.saturating_add(1),
        workspace_id: input.workspace_id,
        user_authority_fact_id: user.user_id,
        user_invite_fact_id: None,
        public_key: crypto::ed25519_public_key(&invite_private_key),
    };
    let device_invite_bytes =
        crate::protocol::facts::identity::signed_fact::create::sign_payload_bytes(
            membership.endpoint_shared_id,
            &local.signing_secret,
            identity::device_invite::layout::encode_fact(&device_invite)?,
        )?;
    let device_invite_fact = Fact::new(
        FactScope::Global,
        device_invite.created_at_ms,
        device_invite_bytes,
    );
    let invite_secret = InviteSecretFact::scoped(
        invite_private_key,
        input.workspace_id,
        device_invite_fact.id,
    );
    let invite_secret_fact = Fact::new(
        FactScope::Local,
        input.created_at_ms.saturating_add(2),
        super::layout::encode_fact(&invite_secret)?,
    );
    let mut facts = endpoint_output.effects.facts;
    facts.push(device_invite_fact.clone());
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

    Ok(CommandOutput::new(CreateInviteReceipt {
        link,
        invite_fact_id: device_invite_fact.id,
        invite_secret_id: invite_secret_fact.id,
        workspace_id: input.workspace_id,
    })
    .with_facts(facts))
}

pub fn create_invite_server(
    ctx: &CommandContext<'_>,
    input: CreateInviteServer,
) -> Result<CommandOutput<CreateInviteReceipt>, String> {
    let endpoint_output =
        identity::endpoint::commands::local_or_create(ctx.store(), input.created_at_ms)?;
    let local = endpoint_output.receipt.endpoint;
    let authority = local_admin_id(ctx.store(), input.workspace_id, local.signing_public_key)?;
    let invite_private_key = crypto::random_ed25519_private_key();
    let invite_server = identity::invite_server::fact::InviteServerFact {
        created_at_ms: input.created_at_ms.saturating_add(1),
        public_key: crypto::ed25519_public_key(&invite_private_key),
        workspace_id: input.workspace_id,
        authority_fact_id: authority.admin_id,
    };
    let invite_server_bytes =
        crate::protocol::facts::identity::signed_fact::create::sign_payload_bytes(
            authority.signer_id,
            &local.signing_secret,
            identity::invite_server::layout::encode_fact(&invite_server)?,
        )?;
    let invite_server_fact = Fact::new(
        FactScope::Global,
        invite_server.created_at_ms,
        invite_server_bytes,
    );
    let invite_secret = InviteSecretFact::scoped(
        invite_private_key,
        input.workspace_id,
        invite_server_fact.id,
    );
    let invite_secret_fact = Fact::new(
        FactScope::Local,
        input.created_at_ms.saturating_add(2),
        super::layout::encode_fact(&invite_secret)?,
    );
    let mut facts = endpoint_output.effects.facts;
    facts.push(invite_server_fact.clone());
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

    Ok(CommandOutput::new(CreateInviteReceipt {
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
    pub request_id: FactId,
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
    ctx: &CommandContext<'_>,
    input: AcceptInvite,
) -> Result<CommandOutput<AcceptInviteReceipt>, String> {
    let endpoint_output =
        identity::endpoint::commands::local_or_create(ctx.store(), input.created_at_ms)?;
    let local = endpoint_output.receipt.endpoint;
    if input.invite.identity_scope {
        if input.from_listen_addr.is_none() {
            return Err("accept requires a running local daemon for workspace invites".to_string());
        }
        reject_duplicate_join(ctx.store(), local.endpoint, input.invite.workspace_id)?;
    }

    let request = connection::request::commands::create(
        connection::request::commands::CreateConnectionRequest {
            created_at_ms: input.created_at_ms.saturating_add(1),
            local_endpoint: local,
            remote_endpoint: input.invite.endpoint,
            bootstrap_secret: input.invite.bootstrap_secret,
            workspace_id: input
                .invite
                .identity_scope
                .then_some(input.invite.workspace_id),
            invite_fact_id: input.invite.invite_fact_id,
            from_listen_addr: input.from_listen_addr,
            to_listen_addr: Some(input.invite.addr),
        },
    )?;
    let mut facts = endpoint_output.effects.facts;
    facts.extend(request.effects.facts);

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
            identity::user::commands::create_signed(identity::user::commands::CreateSignedUser {
                created_at_ms: input.created_at_ms.saturating_add(4),
                workspace_id: input.invite.workspace_id,
                signer_id: input.invite.invite_fact_id,
                signer_private_key: input.invite.bootstrap_secret,
                username,
            })?;
        user_id = Some(user.receipt.user_id);
        facts.extend(user.effects.facts);

        let device_invite = workspace_accept_device_invite_fact(
            input.created_at_ms.saturating_add(5),
            input.invite.workspace_id,
            user.receipt.user_id,
            input.invite.invite_fact_id,
            input.invite.bootstrap_secret,
        )?;

        facts.push(device_invite.clone());
        facts.push(endpoint_shared_fact(
            input.created_at_ms.saturating_add(6),
            input.invite.workspace_id,
            user.receipt.user_id,
            local.endpoint,
            local.signing_public_key,
            &device_name,
            device_invite.id,
            input.invite.bootstrap_secret,
        )?);

        let accepted = identity::invite_accepted::commands::accept(
            identity::invite_accepted::commands::AcceptInvite {
                created_at_ms: input.created_at_ms.saturating_add(7),
                accepted_endpoint_id: local.endpoint,
                bootstrap_secret: input.invite.bootstrap_secret,
                workspace_id: input.invite.workspace_id,
                invite_fact_id: input.invite.invite_fact_id,
            },
        )?;
        facts.extend(accepted.effects.facts);
    }

    Ok(CommandOutput::new(AcceptInviteReceipt {
        connected_addr: input.invite.addr,
        workspace_id: input
            .invite
            .identity_scope
            .then_some(input.invite.workspace_id),
        user_id,
        endpoint_shared_id: None,
        endpoint_role: None,
        request_id: request.receipt.request_id,
    })
    .with_facts(facts))
}

fn workspace_accept_device_invite_fact(
    created_at_ms: u64,
    workspace_id: FactId,
    user_id: FactId,
    user_invite_fact_id: FactId,
    bootstrap_secret: [u8; 32],
) -> Result<Fact, String> {
    let payload = identity::device_invite::fact::DeviceInviteFact {
        created_at_ms,
        workspace_id,
        user_authority_fact_id: user_id,
        user_invite_fact_id: Some(user_invite_fact_id),
        public_key: crypto::ed25519_public_key(&bootstrap_secret),
    };
    let bytes = crate::protocol::facts::identity::signed_fact::create::sign_payload_bytes(
        user_id,
        &bootstrap_secret,
        identity::device_invite::layout::encode_fact(&payload)?,
    )?;
    Ok(Fact::new(FactScope::Global, created_at_ms, bytes))
}

pub fn accept_device_link(
    ctx: &CommandContext<'_>,
    input: AcceptDeviceLink,
) -> Result<CommandOutput<AcceptInviteReceipt>, String> {
    if !input.invite.identity_scope {
        return Err("accept-link requires a workspace-scoped link".to_string());
    }
    if input.from_listen_addr.is_none() {
        return Err("accept-link requires a running local daemon".to_string());
    }
    if input.device_name.trim().is_empty() {
        return Err("device name must not be empty".to_string());
    }
    let user_id = input
        .invite
        .user_authority_fact_id
        .ok_or_else(|| "accept-link requires a USER_ID invite part".to_string())?;
    let endpoint_output =
        identity::endpoint::commands::local_or_create(ctx.store(), input.created_at_ms)?;
    let local = endpoint_output.receipt.endpoint;
    reject_duplicate_join(ctx.store(), local.endpoint, input.invite.workspace_id)?;

    let request = connection::request::commands::create(
        connection::request::commands::CreateConnectionRequest {
            created_at_ms: input.created_at_ms.saturating_add(1),
            local_endpoint: local,
            remote_endpoint: input.invite.endpoint,
            bootstrap_secret: input.invite.bootstrap_secret,
            workspace_id: Some(input.invite.workspace_id),
            invite_fact_id: input.invite.invite_fact_id,
            from_listen_addr: input.from_listen_addr,
            to_listen_addr: Some(input.invite.addr),
        },
    )?;
    let endpoint_shared = endpoint_shared_fact(
        input.created_at_ms.saturating_add(4),
        input.invite.workspace_id,
        user_id,
        local.endpoint,
        local.signing_public_key,
        &input.device_name,
        input.invite.invite_fact_id,
        input.invite.bootstrap_secret,
    )?;
    let accepted = identity::invite_accepted::commands::accept(
        identity::invite_accepted::commands::AcceptInvite {
            created_at_ms: input.created_at_ms.saturating_add(5),
            accepted_endpoint_id: local.endpoint,
            bootstrap_secret: input.invite.bootstrap_secret,
            workspace_id: input.invite.workspace_id,
            invite_fact_id: input.invite.invite_fact_id,
        },
    )?;
    let mut facts = endpoint_output.effects.facts;
    facts.extend(request.effects.facts);
    facts.push(endpoint_shared.clone());
    facts.extend(accepted.effects.facts);

    Ok(CommandOutput::new(AcceptInviteReceipt {
        connected_addr: input.invite.addr,
        workspace_id: Some(input.invite.workspace_id),
        user_id: Some(user_id),
        endpoint_shared_id: Some(endpoint_shared.id),
        endpoint_role: Some(InviteEndpointRole::Device),
        request_id: request.receipt.request_id,
    })
    .with_facts(facts))
}

pub fn accept_invite_server(
    ctx: &CommandContext<'_>,
    input: AcceptInviteServer,
) -> Result<CommandOutput<AcceptInviteReceipt>, String> {
    if !input.invite.identity_scope
        || input.invite.endpoint_role != InviteEndpointRole::InviteServer
    {
        return Err("accept-invite-server requires an invite-server identity invite".to_string());
    }
    if input.invite.user_authority_fact_id.is_some() {
        return Err("invite-server invite must not carry USER_ID".to_string());
    }
    if input.from_listen_addr.is_none() {
        return Err("accept-invite-server requires a running local daemon".to_string());
    }
    if input.device_name.trim().is_empty() {
        return Err("device name must not be empty".to_string());
    }
    let endpoint_output =
        identity::endpoint::commands::local_or_create(ctx.store(), input.created_at_ms)?;
    let local = endpoint_output.receipt.endpoint;
    reject_duplicate_join(ctx.store(), local.endpoint, input.invite.workspace_id)?;

    let request = connection::request::commands::create(
        connection::request::commands::CreateConnectionRequest {
            created_at_ms: input.created_at_ms.saturating_add(1),
            local_endpoint: local,
            remote_endpoint: input.invite.endpoint,
            bootstrap_secret: input.invite.bootstrap_secret,
            workspace_id: Some(input.invite.workspace_id),
            invite_fact_id: input.invite.invite_fact_id,
            from_listen_addr: input.from_listen_addr,
            to_listen_addr: Some(input.invite.addr),
        },
    )?;
    let endpoint_shared = endpoint_shared_fact_with_role(
        input.created_at_ms.saturating_add(4),
        input.invite.workspace_id,
        input.invite.invite_fact_id,
        local.endpoint,
        local.signing_public_key,
        identity::endpoint_shared::fact::EndpointRole::InviteServer,
        &input.device_name,
        input.invite.invite_fact_id,
        input.invite.bootstrap_secret,
    )?;
    let accepted = identity::invite_accepted::commands::accept(
        identity::invite_accepted::commands::AcceptInvite {
            created_at_ms: input.created_at_ms.saturating_add(5),
            accepted_endpoint_id: local.endpoint,
            bootstrap_secret: input.invite.bootstrap_secret,
            workspace_id: input.invite.workspace_id,
            invite_fact_id: input.invite.invite_fact_id,
        },
    )?;
    let mut facts = endpoint_output.effects.facts;
    facts.extend(request.effects.facts);
    facts.push(endpoint_shared.clone());
    facts.extend(accepted.effects.facts);

    Ok(CommandOutput::new(AcceptInviteReceipt {
        connected_addr: input.invite.addr,
        workspace_id: Some(input.invite.workspace_id),
        user_id: None,
        endpoint_shared_id: Some(endpoint_shared.id),
        endpoint_role: Some(InviteEndpointRole::InviteServer),
        request_id: request.receipt.request_id,
    })
    .with_facts(facts))
}

fn endpoint_shared_fact(
    created_at_ms: u64,
    workspace_id: FactId,
    user_id: FactId,
    endpoint_id: FactId,
    signing_public_key: [u8; 32],
    device_name: &str,
    signer_id: FactId,
    signer_private_key: [u8; 32],
) -> Result<Fact, String> {
    endpoint_shared_fact_with_role(
        created_at_ms,
        workspace_id,
        user_id,
        endpoint_id,
        signing_public_key,
        identity::endpoint_shared::fact::EndpointRole::Device,
        device_name,
        signer_id,
        signer_private_key,
    )
}

fn endpoint_shared_fact_with_role(
    created_at_ms: u64,
    workspace_id: FactId,
    user_id: FactId,
    endpoint_id: FactId,
    signing_public_key: [u8; 32],
    endpoint_role: identity::endpoint_shared::fact::EndpointRole,
    device_name: &str,
    signer_id: FactId,
    signer_private_key: [u8; 32],
) -> Result<Fact, String> {
    let endpoint = identity::endpoint_shared::fact::EndpointSharedFact {
        created_at_ms,
        workspace_id,
        user_authority_fact_id: user_id,
        endpoint_id,
        signing_public_key,
        endpoint_role,
        device_name: device_name.to_string(),
    };
    let bytes = crate::protocol::facts::identity::signed_fact::create::sign_payload_bytes(
        signer_id,
        &signer_private_key,
        identity::endpoint_shared::layout::encode_fact(&endpoint)?,
    )?;
    Ok(Fact::new(FactScope::Global, created_at_ms, bytes))
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
    store: &Store,
    workspace_id: FactId,
    signing_public_key: [u8; 32],
) -> Result<LocalAdminAuthority, String> {
    let membership = identity::workspace::local_membership::local_membership(store, workspace_id)?
        .ok_or_else(|| "local endpoint has not joined this workspace".to_string())?;
    if membership.signing_public_key != signing_public_key {
        return Err("local endpoint signing key does not match workspace membership".to_string());
    }

    store
        .table_rows_with_key_prefix(identity::admin::rows::ADMIN_ROWS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load admin rows: {err}"))?
        .into_iter()
        .map(|(key, value)| identity::admin::rows::decode_admin_row(&key, &value))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .find(|admin| admin.user_fact_id == membership.user_authority_fact_id)
        .map(|admin| LocalAdminAuthority {
            admin_id: admin.admin_id,
            signer_id: membership.endpoint_shared_id,
        })
        .ok_or_else(|| "local user is not an admin in this workspace".to_string())
}

fn reject_duplicate_join(
    store: &Store,
    endpoint_id: FactId,
    workspace_id: FactId,
) -> Result<(), String> {
    let mut prefix = Vec::with_capacity(64);
    prefix.extend_from_slice(&endpoint_id);
    prefix.extend_from_slice(&workspace_id);
    if !store
        .table_rows_with_key_prefix(
            identity::invite_accepted::rows::INVITE_ACCEPTED_ROWS,
            &prefix,
            1,
        )
        .map_err(|err| format!("load accepted invites: {err}"))?
        .is_empty()
    {
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
