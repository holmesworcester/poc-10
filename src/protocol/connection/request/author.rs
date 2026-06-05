//! Unified connection-request construction helpers.
//!
//! Bootstrap mode is authorized by an invite-secret signature over canonical
//! request bytes with the invite signature slot zeroed. Membership mode is
//! authorized by the initiator endpoint signing key over canonical request
//! bytes with the endpoint signature slot zeroed.

use crate::core::crypto::{self, Ed25519PublicKey};
use crate::protocol::auth::endpoint::fact::EndpointFact;
use crate::protocol::auth::invite::fact::InviteSecretFact;
use crate::protocol::canonical;

use super::encode;
use super::fact::{ConnectionRequestFact, REQUEST_MODE_BOOTSTRAP, REQUEST_MODE_MEMBERSHIP};

pub fn bootstrap_signature_bytes(request: &ConnectionRequestFact) -> Result<Vec<u8>, String> {
    if request.mode != REQUEST_MODE_BOOTSTRAP {
        return Err("bootstrap request signature requires bootstrap mode".to_string());
    }
    canonical::encode_with_zeroed_fields(
        request,
        encode::encode_fact,
        [encode::INVITE_SIGNATURE_OFFSET..encode::INVITE_SIGNATURE_END],
    )
}

pub fn endpoint_signature_bytes(request: &ConnectionRequestFact) -> Result<Vec<u8>, String> {
    if request.mode != REQUEST_MODE_MEMBERSHIP {
        return Err("membership request signature requires membership mode".to_string());
    }
    canonical::encode_with_zeroed_fields(
        request,
        encode::encode_fact,
        [encode::ENDPOINT_SIGNATURE_OFFSET..encode::ENDPOINT_SIGNATURE_END],
    )
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
        &bootstrap_signature_bytes(request)?,
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
        &endpoint_signature_bytes(request)?,
    );
    Ok(())
}

pub fn sign_request(
    request: &mut ConnectionRequestFact,
    endpoint: &EndpointFact,
) -> Result<(), String> {
    sign_membership_request(request, endpoint)
}

pub fn validate_invite_signature(
    request: &ConnectionRequestFact,
    invite_secret: &InviteSecretFact,
) -> Result<(), String> {
    if request.mode != REQUEST_MODE_BOOTSTRAP {
        return Err("connection request invite validation requires bootstrap mode".to_string());
    }
    if invite_secret.bootstrap_hash != request.bootstrap_hash {
        return Err("connection request bootstrap hash is not authorized".to_string());
    }
    if let Some(invite_fact_id) = invite_secret.invite_fact_id {
        if invite_fact_id != request.invite_fact_id {
            return Err("connection request invite id is not authorized".to_string());
        }
    }
    let public_key = crypto::ed25519_public_key(&invite_secret.bootstrap_secret);
    if !crypto::ed25519_verify(
        &public_key,
        &bootstrap_signature_bytes(request)?,
        &request.invite_signature,
    ) {
        return Err("connection request invite signature is not authorized".to_string());
    }
    Ok(())
}

pub fn validate_endpoint_signature(
    request: &ConnectionRequestFact,
    signing_public_key: &Ed25519PublicKey,
) -> Result<(), String> {
    if request.mode != REQUEST_MODE_MEMBERSHIP {
        return Err("connection request endpoint validation requires membership mode".to_string());
    }
    if !crypto::ed25519_verify(
        signing_public_key,
        &endpoint_signature_bytes(request)?,
        &request.endpoint_signature,
    ) {
        return Err("connection request endpoint signature is not authorized".to_string());
    }
    Ok(())
}

pub fn validate_mode_shape(request: &ConnectionRequestFact) -> Result<(), String> {
    match request.mode {
        REQUEST_MODE_BOOTSTRAP => {
            require_nonzero("invite_fact_id", &request.invite_fact_id)?;
            require_nonzero("bootstrap_hash", &request.bootstrap_hash)?;
            require_nonzero("invite_secret_fact_id", &request.invite_secret_fact_id)?;
            if request.invite_signature == [0; crypto::ED25519_SIGNATURE_BYTES] {
                return Err("bootstrap request invite_signature cannot be empty".to_string());
            }
            require_zero(
                "initiator_endpoint_shared_id",
                &request.initiator_endpoint_shared_id,
            )?;
            if request.endpoint_signature != [0; crypto::ED25519_SIGNATURE_BYTES] {
                return Err("bootstrap request endpoint_signature must be zero".to_string());
            }
        }
        REQUEST_MODE_MEMBERSHIP => {
            require_zero("invite_fact_id", &request.invite_fact_id)?;
            require_zero("bootstrap_hash", &request.bootstrap_hash)?;
            require_zero("invite_secret_fact_id", &request.invite_secret_fact_id)?;
            if request.invite_signature != [0; crypto::ED25519_SIGNATURE_BYTES] {
                return Err("membership request invite_signature must be zero".to_string());
            }
            require_nonzero(
                "initiator_endpoint_shared_id",
                &request.initiator_endpoint_shared_id,
            )?;
            if request.endpoint_signature == [0; crypto::ED25519_SIGNATURE_BYTES] {
                return Err("membership request endpoint_signature cannot be empty".to_string());
            }
        }
        other => return Err(format!("unknown connection request mode {other}")),
    }
    Ok(())
}

fn require_nonzero(name: &str, value: &[u8; 32]) -> Result<(), String> {
    if value == &[0; 32] {
        Err(format!("connection request {name} cannot be empty"))
    } else {
        Ok(())
    }
}

fn require_zero(name: &str, value: &[u8; 32]) -> Result<(), String> {
    if value != &[0; 32] {
        Err(format!("connection request inactive {name} must be zero"))
    } else {
        Ok(())
    }
}
