//! User-facing constructor for membership connection requests.
//!
//! `connect` to a known peer creates the local facts that start a membership
//! handshake: an initiator ephemeral secret and a global connection request
//! signed by the local endpoint signing key. There is no invite material; the
//! request carries the initiator's `endpoint_shared` membership id as its
//! authorization witness.
//!
//! Commands do not project, open sockets, or send bytes. Projection decides when
//! the request is admissible and emits the network send; this file owns only
//! user-facing construction and receipt shape.

use std::net::SocketAddr;

use crate::core::cli::encode_hex;
use crate::core::command_context::{CommandContext, CommandOutput};
use crate::core::crypto;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::protocol::auth::endpoint::create::local_endpoint;
use crate::protocol::auth::endpoint::fact::EndpointFact;

use super::queries::choose_connection_mode;

pub const CONNECT_USAGE: &str = "connect ENDPOINT_ID_HEX";
use crate::protocol::connection::ephemeral_secret::fact::ConnectionEphemeralSecretFact;
use crate::protocol::connection::ephemeral_secret::layout as ephemeral_layout;

use super::fact::ConnectionRequestFact;
use super::{create as request_create, layout};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateConnectionRequest {
    pub created_at_ms: u64,
    pub local_endpoint: EndpointFact,
    pub remote_endpoint: FactId,
    pub initiator_endpoint_shared_id: FactId,
    pub from_listen_addr: Option<SocketAddr>,
    pub to_listen_addr: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateConnectionRequestReceipt {
    pub request_id: FactId,
    pub initiator_ephemeral_secret_id: FactId,
}

pub fn create(
    input: CreateConnectionRequest,
) -> Result<CommandOutput<CreateConnectionRequestReceipt>, String> {
    validate_id("remote_endpoint", &input.remote_endpoint)?;
    validate_id("initiator_endpoint_shared_id", &input.initiator_endpoint_shared_id)?;

    let ephemeral_private_key = crypto::random_x25519_private_key();
    let ephemeral = ConnectionEphemeralSecretFact {
        owner_endpoint: input.local_endpoint.endpoint,
        ephemeral_private_key,
        ephemeral_public_key: crypto::x25519_public_key(&ephemeral_private_key),
        created_at_ms: input.created_at_ms.saturating_add(1),
    };
    let ephemeral_fact = Fact::new(
        FactScope::Local,
        input.created_at_ms.saturating_add(1),
        ephemeral_layout::encode_fact(&ephemeral)?,
    );

    let mut request = ConnectionRequestFact {
        from_endpoint: input.local_endpoint.endpoint,
        to_endpoint: input.remote_endpoint,
        nonce: crypto::random_bytes_32(),
        initiator_endpoint_shared_id: input.initiator_endpoint_shared_id,
        initiator_ephemeral_secret_fact_id: ephemeral_fact.id,
        initiator_ephemeral_public_key: ephemeral.ephemeral_public_key,
        endpoint_signature: [0; crypto::ED25519_SIGNATURE_BYTES],
        from_listen_addr: input.from_listen_addr,
        to_listen_addr: input.to_listen_addr,
    };
    request_create::sign_request(&mut request, &input.local_endpoint)?;
    let request_fact = Fact::new(
        FactScope::Local,
        input.created_at_ms.saturating_add(2),
        layout::encode_fact(&request)?,
    );

    Ok(CommandOutput::new(CreateConnectionRequestReceipt {
        request_id: request_fact.id,
        initiator_ephemeral_secret_id: ephemeral_fact.id,
    })
    .with_facts(vec![ephemeral_fact, request_fact]))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Connect {
    pub created_at_ms: u64,
    pub target_endpoint: FactId,
    pub from_listen_addr: Option<SocketAddr>,
}

/// Build a membership connection request to a known peer, using the
/// connection-mode trigger. Errors if no membership connection is available
/// (the peer is unknown or has not synced our membership yet) — the caller
/// should accept an invite to bootstrap first.
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
    create(CreateConnectionRequest {
        created_at_ms: input.created_at_ms,
        local_endpoint: local,
        remote_endpoint: plan.to_endpoint,
        initiator_endpoint_shared_id: plan.initiator_endpoint_shared_id,
        from_listen_addr: input.from_listen_addr,
        to_listen_addr: Some(plan.addr),
    })
}

fn validate_id(name: &str, id: &FactId) -> Result<(), String> {
    if id == &[0; 32] {
        Err(format!("{name} cannot be empty"))
    } else {
        Ok(())
    }
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
    fn create_request_builds_ephemeral_and_endpoint_signed_request() {
        let local = endpoint();
        let output = create(CreateConnectionRequest {
            created_at_ms: 10,
            local_endpoint: local,
            remote_endpoint: [9; 32],
            initiator_endpoint_shared_id: [2; 32],
            from_listen_addr: Some("127.0.0.1:41000".parse().unwrap()),
            to_listen_addr: Some("127.0.0.1:41001".parse().unwrap()),
        })
        .expect("create request");

        assert_eq!(output.effects.facts.len(), 2);
        assert_eq!(
            output.receipt.initiator_ephemeral_secret_id,
            output.effects.facts[0].id
        );
        assert_eq!(output.receipt.request_id, output.effects.facts[1].id);
        let request = layout::decode_fact(&output.effects.facts[1].bytes).expect("decode request");
        request_create::validate_endpoint_signature(&request, &local.signing_public_key)
            .expect("signature verifies against local membership signing key");
    }
}
