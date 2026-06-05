//! Unified connection-request construction helpers.
//!
//! Bootstrap mode is authorized by an invite-secret signature over canonical
//! request bytes with the invite signature slot zeroed. Membership mode is
//! authorized by the initiator endpoint signing key over canonical request
//! bytes with the endpoint signature slot zeroed.

use crate::core::crypto;
use crate::protocol::auth::endpoint::fact::EndpointFact;
use crate::protocol::auth::invite::fact::InviteSecretFact;

use super::encode;
use super::fact::{ConnectionRequestFact, REQUEST_MODE_BOOTSTRAP, REQUEST_MODE_MEMBERSHIP};

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
