//! User-facing constructors for connection requests.
//!
//! Accepting an invite creates the local facts needed to start a handshake:
//! scoped invite secret, initiator ephemeral secret, and a local
//! `bootstrap_request_sent` lifecycle fact containing the semantic request and
//! exact sealed bytes. The command returns those facts plus a typed receipt so
//! the caller can submit them through the normal runtime path.
//!
//! Commands do not project, open sockets, or send bytes. Projection decides when
//! the request is admissible and emits bootstrap network work from the lifecycle
//! fact; this file owns only user-facing construction and receipt shape.

use std::net::SocketAddr;

use crate::core::command_context::CommandOutput;
use crate::core::crypto;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::protocol::auth;
use crate::protocol::auth::endpoint::fact::EndpointFact;
use crate::protocol::auth::invite::fact::InviteSecretFact;
use crate::protocol::connection::bootstrap_request_sent::{
    fact::BootstrapRequestSentFact, layout as request_sent_layout,
};
use crate::protocol::connection::ephemeral_secret::fact::ConnectionEphemeralSecretFact;
use crate::protocol::connection::ephemeral_secret::layout as ephemeral_layout;

use super::fact::BootstrapRequestFact;
use super::{create as request_create, layout, transit};

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
        auth::invite::layout::encode_fact(&invite_secret)?,
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

    let mut request = BootstrapRequestFact {
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
    let request_bytes = layout::encode_fact(&request)?;
    let request_id = crate::core::facts::fact_id(&request_bytes);
    let sealed_request_bytes =
        transit::seal_connection_request(&request_bytes, &ephemeral.ephemeral_private_key)?;
    let sealed_request_bytes = sealed_request_bytes
        .as_slice()
        .try_into()
        .map_err(|_| "sealed bootstrap request has unexpected byte length".to_string())?;
    let peer_addr = input
        .to_listen_addr
        .ok_or_else(|| "bootstrap connection request requires a peer address".to_string())?;
    let request_sent = BootstrapRequestSentFact {
        request_id,
        initiator_ephemeral_secret_fact_id: ephemeral_fact.id,
        peer_addr,
        request,
        sealed_request_bytes,
        created_at_ms: input.created_at_ms.saturating_add(2),
    };
    let request_sent_fact = Fact::new(
        FactScope::Local,
        input.created_at_ms.saturating_add(2),
        request_sent_layout::encode_fact(&request_sent)?,
    );

    Ok(CommandOutput::new(CreateConnectionRequestReceipt {
        request_id,
        invite_secret_id: invite_secret_fact.id,
        initiator_ephemeral_secret_id: ephemeral_fact.id,
    })
    .with_facts(vec![invite_secret_fact, ephemeral_fact, request_sent_fact]))
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
    use crate::protocol::auth::endpoint::fact::EndpointFact;

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

        assert_eq!(output.effects.facts.len(), 3);
        assert_eq!(output.receipt.invite_secret_id, output.effects.facts[0].id);
        assert_eq!(
            output.receipt.initiator_ephemeral_secret_id,
            output.effects.facts[1].id
        );
        let sent = request_sent_layout::decode_fact(&output.effects.facts[2].bytes)
            .expect("decode request sent");
        assert_eq!(output.receipt.request_id, sent.request_id);
        assert_eq!(
            sent.sealed_request_bytes[0],
            transit::TYPE_SEALED_CONNECTION_REQUEST
        );
        let request = sent.request;
        let public_key = crypto::ed25519_public_key(&[7; 32]);
        assert!(crypto::ed25519_verify(
            &public_key,
            &request_create::invite_signing_transcript(&request).expect("transcript"),
            &request.invite_signature
        ));
    }
}
