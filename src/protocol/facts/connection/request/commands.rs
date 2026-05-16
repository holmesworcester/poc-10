//! Command constructors for bootstrap connection requests.
//!
//! Accepting an invite creates local bootstrap context and one shared
//! connection request:
//!
//! ```text
//! invite link + local endpoint
//!   -> local scoped invite-secret fact
//!   -> local connection-ephemeral-secret fact
//!   -> global connection-request fact
//! ```
//!
//! The command does not open sockets. The CLI/runtime submits the returned
//! facts and lets a bootstrap-send handler perform the network attempt.

use std::net::SocketAddr;

use crate::core::command_context::CommandOutput;
use crate::core::crypto;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::protocol::facts::connection::ephemeral_secret::fact::ConnectionEphemeralSecretFact;
use crate::protocol::facts::connection::ephemeral_secret::layout as ephemeral_layout;
use crate::protocol::facts::identity;
use crate::protocol::facts::identity::endpoint::fact::EndpointFact;
use crate::protocol::facts::identity::invite::fact::InviteSecretFact;

use super::fact::ConnectionRequestFact;
use super::{create as request_create, layout};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateConnectionRequest {
    pub created_at_ms: u64,
    pub local_endpoint: EndpointFact,
    pub remote_endpoint: FactId,
    pub bootstrap_secret: [u8; 32],
    pub workspace_id: Option<FactId>,
    pub invite_fact_id: FactId,
    pub from_listen_addr: Option<SocketAddr>,
    pub to_listen_addr: Option<SocketAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateConnectionRequestReceipt {
    pub request_id: FactId,
    pub invite_secret_id: FactId,
    pub initiator_ephemeral_secret_id: FactId,
}

pub fn create(
    input: CreateConnectionRequest,
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
        identity::invite::layout::encode_fact(&invite_secret)?,
    );

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
        invite_fact_id: input.invite_fact_id,
        bootstrap_hash: invite_secret.bootstrap_hash,
        invite_signature: [0; crypto::ED25519_SIGNATURE_BYTES],
        invite_secret_fact_id: invite_secret_fact.id,
        initiator_ephemeral_secret_fact_id: ephemeral_fact.id,
        initiator_ephemeral_public_key: ephemeral.ephemeral_public_key,
        from_listen_addr: input.from_listen_addr,
        to_listen_addr: input.to_listen_addr,
    };
    request.invite_signature = crypto::ed25519_sign(
        &invite_secret.bootstrap_secret,
        &request_create::invite_signing_transcript(&request)?,
    );
    let request_fact = Fact::new(
        FactScope::Local,
        input.created_at_ms.saturating_add(2),
        layout::encode_fact(&request)?,
    );

    Ok(CommandOutput::new(CreateConnectionRequestReceipt {
        request_id: request_fact.id,
        invite_secret_id: invite_secret_fact.id,
        initiator_ephemeral_secret_id: ephemeral_fact.id,
    })
    .with_facts(vec![invite_secret_fact, ephemeral_fact, request_fact]))
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
    use crate::core::crypto;
    use crate::protocol::facts::identity::endpoint::fact::EndpointFact;

    use super::*;

    #[test]
    fn create_request_builds_local_secret_ephemeral_and_signed_request() {
        let local_secret = [3; 32];
        let local_signing_secret = [5; 32];
        let local_endpoint = EndpointFact {
            endpoint: crypto::x25519_public_key(&local_secret),
            secret: local_secret,
            signing_public_key: crypto::ed25519_public_key(&local_signing_secret),
            signing_secret: local_signing_secret,
        };

        let output = create(CreateConnectionRequest {
            created_at_ms: 10,
            local_endpoint,
            remote_endpoint: [9; 32],
            bootstrap_secret: [7; 32],
            workspace_id: Some([1; 32]),
            invite_fact_id: [2; 32],
            from_listen_addr: Some("127.0.0.1:41000".parse().unwrap()),
            to_listen_addr: Some("127.0.0.1:41001".parse().unwrap()),
        })
        .expect("create request");

        assert_eq!(output.facts.len(), 3);
        assert_eq!(output.receipt.invite_secret_id, output.facts[0].id);
        assert_eq!(
            output.receipt.initiator_ephemeral_secret_id,
            output.facts[1].id
        );
        assert_eq!(output.receipt.request_id, output.facts[2].id);
        let request = layout::decode_fact(&output.facts[2].bytes).expect("decode request");
        let public_key = crypto::ed25519_public_key(&[7; 32]);
        assert!(crypto::ed25519_verify(
            &public_key,
            &request_create::invite_signing_transcript(&request).expect("transcript"),
            &request.invite_signature
        ));
    }
}
