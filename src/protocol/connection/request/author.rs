//! Unified connection-request construction helpers.
//!
//! Bootstrap mode is authorized by an invite-secret signature over canonical
//! request bytes with the invite signature slot zeroed. Membership mode is
//! authorized by the initiator endpoint signing key over canonical request
//! bytes with the endpoint signature slot zeroed.

use crate::core::crypto;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::protocol::auth::endpoint::fact::EndpointFact;
use crate::protocol::auth::invite_secret::fact::InviteSecretFact;
use crate::protocol::connection::ephemeral_secret::author as ephemeral_author;

use super::fact::{ConnectionRequestFact, REQUEST_MODE_BOOTSTRAP, REQUEST_MODE_MEMBERSHIP};
use super::{encode, project::decode};

use std::net::SocketAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CreateBootstrapConnectionAttempt {
    pub created_at_ms: u64,
    pub local_endpoint: EndpointFact,
    pub remote_endpoint: FactId,
    pub invite_secret: InviteSecretFact,
    pub invite_fact_id: FactId,
    pub dialed_addr: SocketAddr,
    pub initiator_addr: Option<SocketAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapConnectionAttempt {
    pub request_id: FactId,
    pub invite_secret_id: FactId,
    pub initiator_ephemeral_secret_id: FactId,
    pub ephemeral_secret_fact: Fact,
    pub request_fact: Fact,
}

pub fn create_bootstrap_attempt(
    input: CreateBootstrapConnectionAttempt,
) -> Result<BootstrapConnectionAttempt, String> {
    validate_id("remote_endpoint", &input.remote_endpoint)?;
    validate_id("invite_fact_id", &input.invite_fact_id)?;
    let invite_secret = input.invite_secret.validate()?;
    let invite_secret_fact =
        crate::protocol::auth::invite_secret::author::secret_fact(invite_secret, input.created_at_ms)?;
    let (ephemeral, ephemeral_fact) = ephemeral_author::random_secret_fact(
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
    sign_bootstrap_request(&mut request, &invite_secret)?;
    let sealed = encode::seal_fact(&request, &ephemeral.ephemeral_private_key)?;
    let request_fact = Fact::new(
        FactScope::Global,
        input.created_at_ms.saturating_add(2),
        sealed,
    );

    Ok(BootstrapConnectionAttempt {
        request_id: request_fact.id,
        invite_secret_id: invite_secret_fact.id,
        initiator_ephemeral_secret_id: ephemeral_fact.id,
        ephemeral_secret_fact: ephemeral_fact,
        request_fact,
    })
}

pub fn sign_bootstrap_request(
    request: &mut ConnectionRequestFact,
    invite_secret: &InviteSecretFact,
) -> Result<(), String> {
    if request.mode != REQUEST_MODE_BOOTSTRAP {
        return Err("bootstrap connection request has wrong mode".to_string());
    }
    request.invite_signature = crypto::ed25519_sign(
        &invite_secret.bootstrap_secret,
        &encode::bootstrap_signature_bytes(request)?,
    );
    Ok(())
}

pub fn sign_membership_request(
    request: &mut ConnectionRequestFact,
    endpoint: &EndpointFact,
) -> Result<(), String> {
    if request.mode != REQUEST_MODE_MEMBERSHIP {
        return Err("membership connection request has wrong mode".to_string());
    }
    if endpoint.endpoint != request.from_endpoint {
        return Err("membership connection request signer is not the initiator".to_string());
    }
    request.endpoint_signature = crypto::ed25519_sign(
        &endpoint.signing_secret,
        &encode::endpoint_signature_bytes(request)?,
    );
    Ok(())
}

pub fn sign_request(
    request: &mut ConnectionRequestFact,
    endpoint: &EndpointFact,
) -> Result<(), String> {
    sign_membership_request(request, endpoint)
}

pub fn fact_from_sealed_wire(bytes: &[u8], local_timestamp_ms: u64) -> Result<Fact, String> {
    decode::validate_sealed_fact(bytes)?;
    Ok(Fact::new(
        FactScope::Global,
        local_timestamp_ms,
        bytes.to_vec(),
    ))
}

fn validate_id(name: &str, id: &FactId) -> Result<(), String> {
    if id == &[0; 32] {
        Err(format!("{name} cannot be empty"))
    } else {
        Ok(())
    }
}
