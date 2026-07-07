//! Building the membership connection-request facts from an explicit snapshot.
//!
//! Given the local endpoint, the target endpoint, the initiator's
//! `endpoint_shared` membership id, and the listen addresses, this constructs
//! the two local facts that start a membership handshake: an initiator ephemeral
//! secret and the signed connection request. It derives the request's signing
//! transcript via `encode`, signs with the local endpoint signing key, and
//! self-authenticates the request (the write pipeline's exit gate).
//!
//! These are pure constructors: no store reads, no projection, no sockets.
//! `commands.rs` gathers the snapshot from the runtime and calls in here.

use std::net::SocketAddr;

use crate::core::command_context::CommandOutput;
use crate::core::crypto;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::projectors::authenticate_authored;
use crate::protocol::auth::endpoint::fact::EndpointFact;
use crate::protocol::connection::ephemeral_secret::fact::ConnectionEphemeralSecretFact;
use crate::protocol::connection::ephemeral_secret::layout as ephemeral_layout;

use super::authenticate::ConnectionRequestAuthenticator;
use super::encode;
use super::fact::ConnectionRequestFact;

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
    validate_id(
        "initiator_endpoint_shared_id",
        &input.initiator_endpoint_shared_id,
    )?;

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
    encode::sign_request(&mut request, &input.local_endpoint)?;
    let request_fact = Fact::new(
        FactScope::Local,
        input.created_at_ms.saturating_add(2),
        encode::encode_fact(&request)?,
    );
    // Write-pipeline exit gate: never emit a request we cannot authenticate. The
    // endpoint signature parks on the initiator endpoint_shared context the
    // author already satisfied, so a well-formed request passes (it is not
    // Invalid).
    authenticate_authored::<ConnectionRequestAuthenticator>(&request_fact)?;

    Ok(CommandOutput::new(CreateConnectionRequestReceipt {
        request_id: request_fact.id,
        initiator_ephemeral_secret_id: ephemeral_fact.id,
    })
    .with_facts(vec![ephemeral_fact, request_fact]))
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
        let request = super::super::decode::decode_fact(&output.effects.facts[1].bytes)
            .expect("decode request");
        encode::validate_endpoint_signature(&request, &local.signing_public_key)
            .expect("signature verifies against local membership signing key");
    }
}
