//! User-facing constructors for unified connection requests.
//!
//! Commands create local secret facts plus the sealed `connection_request` fact.
//! Projection turns the request into retryable send state; there is no separate
//! request-sent lifecycle fact.

use std::net::SocketAddr;

use crate::core::cli::encode_hex;
use crate::core::command_context::{CommandContext, CommandOutput};
use crate::core::crypto;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::protocol::auth;
use crate::protocol::auth::endpoint::author::local_endpoint;
use crate::protocol::auth::endpoint::fact::EndpointFact;
use crate::protocol::auth::invite::fact::InviteSecretFact;
use crate::protocol::connection::ephemeral_secret::encode as ephemeral_encode;
use crate::protocol::connection::ephemeral_secret::fact::ConnectionEphemeralSecretFact;

use super::fact::{ConnectionRequestFact, REQUEST_MODE_BOOTSTRAP, REQUEST_MODE_MEMBERSHIP};
use super::queries::choose_connection_mode;
use super::{author as request_create, encode};

pub const CONNECT_USAGE: &str = "connect ENDPOINT_ID_HEX ADDR";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateBootstrapConnectionRequest {
    pub created_at_ms: u64,
    pub local_endpoint: EndpointFact,
    pub remote_endpoint: FactId,
    pub bootstrap_secret: [u8; 32],
    pub workspace_id: Option<FactId>,
    pub invite_fact_id: FactId,
    pub dialed_addr: SocketAddr,
    pub initiator_addr: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateMembershipConnectionRequest {
    pub created_at_ms: u64,
    pub local_endpoint: EndpointFact,
    pub remote_endpoint: FactId,
    pub initiator_endpoint_shared_id: FactId,
    pub dialed_addr: SocketAddr,
    pub initiator_addr: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateConnectionRequestReceipt {
    pub request_id: FactId,
    pub invite_secret_id: Option<FactId>,
    pub initiator_ephemeral_secret_id: FactId,
}

pub fn create_bootstrap(
    input: CreateBootstrapConnectionRequest,
) -> Result<CommandOutput<CreateConnectionRequestReceipt>, String> {
    validate_id("remote_endpoint", &input.remote_endpoint)?;
    validate_id("invite_fact_id", &input.invite_fact_id)?;
    if input.bootstrap_secret == [0; 32] {
        return Err("bootstrap_secret cannot be empty".to_string());
    }

    let invite_secret = match input.workspace_id {
        Some(workspace_id) => {
            validate_id("workspace_id", &workspace_id)?;
            InviteSecretFact::scoped(input.bootstrap_secret, workspace_id, input.invite_fact_id)
        }
        None => InviteSecretFact::new(input.bootstrap_secret),
    };
    let invite_secret_fact = Fact::new(
        FactScope::Local,
        input.created_at_ms,
        auth::invite::encode::encode_fact(&invite_secret)?,
    );
    let (ephemeral, ephemeral_fact) = ephemeral_fact(
        input.local_endpoint.endpoint,
        input.created_at_ms.saturating_add(1),
    )?;

    let mut request = ConnectionRequestFact {
        mode: REQUEST_MODE_BOOTSTRAP,
        from_endpoint: input.local_endpoint.endpoint,
        to_endpoint: input.remote_endpoint,
        nonce: crypto::random_bytes_32(),
        dialed_addr: Some(input.dialed_addr),
        initiator_addr: input.initiator_addr,
        invite_fact_id: input.invite_fact_id,
        bootstrap_hash: invite_secret.bootstrap_hash,
        invite_secret_fact_id: invite_secret_fact.id,
        invite_signature: [0; crypto::ED25519_SIGNATURE_BYTES],
        initiator_endpoint_shared_id: [0; 32],
        endpoint_signature: [0; crypto::ED25519_SIGNATURE_BYTES],
        initiator_ephemeral_secret_fact_id: ephemeral_fact.id,
        initiator_ephemeral_public_key: ephemeral.ephemeral_public_key,
    };
    request_create::sign_bootstrap_request(&mut request, &invite_secret)?;
    let request_fact = sealed_request_fact(
        &request,
        &ephemeral.ephemeral_private_key,
        input.created_at_ms.saturating_add(2),
    )?;

    Ok(CommandOutput::new(CreateConnectionRequestReceipt {
        request_id: request_fact.id,
        invite_secret_id: Some(invite_secret_fact.id),
        initiator_ephemeral_secret_id: ephemeral_fact.id,
    })
    .with_facts(vec![invite_secret_fact, ephemeral_fact, request_fact]))
}

pub fn create_membership(
    input: CreateMembershipConnectionRequest,
) -> Result<CommandOutput<CreateConnectionRequestReceipt>, String> {
    validate_id("remote_endpoint", &input.remote_endpoint)?;
    validate_id(
        "initiator_endpoint_shared_id",
        &input.initiator_endpoint_shared_id,
    )?;

    let (ephemeral, ephemeral_fact) = ephemeral_fact(
        input.local_endpoint.endpoint,
        input.created_at_ms.saturating_add(1),
    )?;
    let mut request = ConnectionRequestFact {
        mode: REQUEST_MODE_MEMBERSHIP,
        from_endpoint: input.local_endpoint.endpoint,
        to_endpoint: input.remote_endpoint,
        nonce: crypto::random_bytes_32(),
        dialed_addr: Some(input.dialed_addr),
        initiator_addr: input.initiator_addr,
        invite_fact_id: [0; 32],
        bootstrap_hash: [0; 32],
        invite_secret_fact_id: [0; 32],
        invite_signature: [0; crypto::ED25519_SIGNATURE_BYTES],
        initiator_endpoint_shared_id: input.initiator_endpoint_shared_id,
        endpoint_signature: [0; crypto::ED25519_SIGNATURE_BYTES],
        initiator_ephemeral_secret_fact_id: ephemeral_fact.id,
        initiator_ephemeral_public_key: ephemeral.ephemeral_public_key,
    };
    request_create::sign_membership_request(&mut request, &input.local_endpoint)?;
    let request_fact = sealed_request_fact(
        &request,
        &ephemeral.ephemeral_private_key,
        input.created_at_ms.saturating_add(2),
    )?;

    Ok(CommandOutput::new(CreateConnectionRequestReceipt {
        request_id: request_fact.id,
        invite_secret_id: None,
        initiator_ephemeral_secret_id: ephemeral_fact.id,
    })
    .with_facts(vec![ephemeral_fact, request_fact]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Connect {
    pub created_at_ms: u64,
    pub target_endpoint: FactId,
    pub dialed_addr: SocketAddr,
    pub from_listen_addr: Option<SocketAddr>,
}

/// Build a membership connection request to a known endpoint.
pub fn connect(
    ctx: &CommandContext<'_>,
    input: Connect,
) -> Result<CommandOutput<CreateConnectionRequestReceipt>, String> {
    if input.from_listen_addr.is_none() {
        return Err("connect requires a running local daemon".to_string());
    }
    let local = local_endpoint(ctx.store())?
        .ok_or_else(|| "connect requires a local endpoint identity".to_string())?;
    let plan = choose_connection_mode(ctx.store(), input.target_endpoint)?.ok_or_else(|| {
        format!(
            "no membership connection available for {}; accept an invite to bootstrap first",
            encode_hex(&input.target_endpoint)
        )
    })?;
    create_membership(CreateMembershipConnectionRequest {
        created_at_ms: input.created_at_ms,
        local_endpoint: local,
        remote_endpoint: plan.to_endpoint,
        initiator_endpoint_shared_id: plan.initiator_endpoint_shared_id,
        dialed_addr: input.dialed_addr,
        initiator_addr: input.from_listen_addr,
    })
}

fn ephemeral_fact(
    owner_endpoint: FactId,
    created_at_ms: u64,
) -> Result<(ConnectionEphemeralSecretFact, Fact), String> {
    let ephemeral_private_key = crypto::random_x25519_private_key();
    let ephemeral = ConnectionEphemeralSecretFact {
        owner_endpoint,
        ephemeral_private_key,
        ephemeral_public_key: crypto::x25519_public_key(&ephemeral_private_key),
        created_at_ms,
    };
    let fact = Fact::new(
        FactScope::Local,
        created_at_ms,
        ephemeral_encode::encode_fact(&ephemeral)?,
    );
    Ok((ephemeral, fact))
}

fn sealed_request_fact(
    request: &ConnectionRequestFact,
    ephemeral_private_key: &[u8; 32],
    created_at_ms: u64,
) -> Result<Fact, String> {
    request_create::validate_mode_shape(request)?;
    let sealed = encode::seal_fact(request, ephemeral_private_key)?;
    Ok(Fact::new(FactScope::Global, created_at_ms, sealed))
}

fn validate_id(name: &str, id: &FactId) -> Result<(), String> {
    if id == &[0; 32] {
        Err(format!("{name} cannot be empty"))
    } else {
        Ok(())
    }
}

// Compatibility for older call sites that imported the membership constructor
// as `request::commands::create`.
pub type CreateConnectionRequest = CreateMembershipConnectionRequest;

pub fn create(
    input: CreateConnectionRequest,
) -> Result<CommandOutput<CreateConnectionRequestReceipt>, String> {
    create_membership(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint() -> EndpointFact {
        let local_secret = [3; 32];
        let signing_secret = [5; 32];
        EndpointFact {
            endpoint: crypto::x25519_public_key(&local_secret),
            secret: local_secret,
            signing_public_key: crypto::ed25519_public_key(&signing_secret),
            signing_secret,
        }
    }

    #[test]
    fn membership_create_builds_ephemeral_and_endpoint_signed_request() {
        let local = endpoint();
        let output = create_membership(CreateMembershipConnectionRequest {
            created_at_ms: 10,
            local_endpoint: local,
            remote_endpoint: [9; 32],
            initiator_endpoint_shared_id: [2; 32],
            dialed_addr: "127.0.0.1:41001".parse().unwrap(),
            initiator_addr: Some("127.0.0.1:41000".parse().unwrap()),
        })
        .expect("create request");

        assert_eq!(output.effects.facts.len(), 2);
        assert_eq!(
            output.receipt.initiator_ephemeral_secret_id,
            output.effects.facts[0].id
        );
        assert_eq!(output.receipt.request_id, output.effects.facts[1].id);
        assert_eq!(
            output.effects.facts[1].body()[0],
            encode::TYPE_CONNECTION_REQUEST
        );
    }

    #[test]
    fn bootstrap_create_builds_invite_secret_ephemeral_and_request() {
        let local = endpoint();
        let output = create_bootstrap(CreateBootstrapConnectionRequest {
            created_at_ms: 10,
            local_endpoint: local,
            remote_endpoint: [9; 32],
            bootstrap_secret: [7; 32],
            workspace_id: Some([1; 32]),
            invite_fact_id: [2; 32],
            dialed_addr: "127.0.0.1:41001".parse().unwrap(),
            initiator_addr: Some("127.0.0.1:41000".parse().unwrap()),
        })
        .expect("create request");

        assert_eq!(output.effects.facts.len(), 3);
        assert_eq!(
            output.receipt.invite_secret_id,
            Some(output.effects.facts[0].id)
        );
        assert_eq!(
            output.receipt.initiator_ephemeral_secret_id,
            output.effects.facts[1].id
        );
        assert_eq!(output.receipt.request_id, output.effects.facts[2].id);
    }
}
