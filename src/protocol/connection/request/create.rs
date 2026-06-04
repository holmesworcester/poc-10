//! Unified connection-request construction helpers.
//!
//! Bootstrap mode is authorized by an invite-secret signature. Membership mode
//! is authorized by the initiator endpoint signing key and verified against the
//! initiator's endpoint-shared fact.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::core::crypto::{self, Ed25519PublicKey};
use crate::core::wire;
use crate::protocol::auth::endpoint::fact::EndpointFact;
use crate::protocol::auth::invite::fact::InviteSecretFact;

use super::fact::{ConnectionRequestFact, REQUEST_MODE_BOOTSTRAP, REQUEST_MODE_MEMBERSHIP};

const BOOTSTRAP_TRANSCRIPT_LABEL: &[u8] =
    b"topo-connection-request-bootstrap-signing-transcript-v2";
const MEMBERSHIP_TRANSCRIPT_LABEL: &[u8] =
    b"topo-connection-request-membership-signing-transcript-v2";

pub const ADDR_BLOCK_BYTES: usize = 19;
pub const ADDR_FAMILY_NONE: u8 = 0;
pub const ADDR_FAMILY_V4: u8 = 1;
pub const ADDR_FAMILY_V6: u8 = 2;

pub fn encode_optional_addr(addr: Option<SocketAddr>) -> Result<[u8; ADDR_BLOCK_BYTES], String> {
    let mut out = [0u8; ADDR_BLOCK_BYTES];
    match addr {
        None => {
            out[0] = ADDR_FAMILY_NONE;
        }
        Some(addr) => match addr.ip() {
            IpAddr::V4(ip) => {
                out[0] = ADDR_FAMILY_V4;
                out[1..5].copy_from_slice(&ip.octets());
                wire::put_u16be(addr.port(), &mut out[17..19]).map_err(addr_wire_err)?;
            }
            IpAddr::V6(ip) => {
                out[0] = ADDR_FAMILY_V6;
                out[1..17].copy_from_slice(&ip.octets());
                wire::put_u16be(addr.port(), &mut out[17..19]).map_err(addr_wire_err)?;
            }
        },
    }
    Ok(out)
}

pub fn decode_optional_addr(bytes: &[u8; ADDR_BLOCK_BYTES]) -> Result<Option<SocketAddr>, String> {
    let family = bytes[0];
    let raw = &bytes[1..17];
    let port = wire::take_u16be(&bytes[17..19]).map_err(addr_wire_err)?;
    match family {
        ADDR_FAMILY_NONE => {
            if raw.iter().any(|byte| *byte != 0) || port != 0 {
                return Err("absent connection addr must zero its address bytes".to_string());
            }
            Ok(None)
        }
        ADDR_FAMILY_V4 => {
            if raw[4..].iter().any(|byte| *byte != 0) {
                return Err("ipv4 connection addr must zero its trailing bytes".to_string());
            }
            let octets = [raw[0], raw[1], raw[2], raw[3]];
            Ok(Some(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::from(octets)),
                port,
            )))
        }
        ADDR_FAMILY_V6 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(raw);
            Ok(Some(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                port,
            )))
        }
        other => Err(format!("unknown connection addr family {other}")),
    }
}

fn addr_wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

pub fn bootstrap_signing_transcript(request: &ConnectionRequestFact) -> Result<Vec<u8>, String> {
    if request.mode != REQUEST_MODE_BOOTSTRAP {
        return Err("bootstrap request transcript requires bootstrap mode".to_string());
    }
    let mut out = Vec::new();
    out.extend_from_slice(BOOTSTRAP_TRANSCRIPT_LABEL);
    out.push(request.mode);
    out.extend_from_slice(&request.from_endpoint);
    out.extend_from_slice(&request.to_endpoint);
    out.extend_from_slice(&request.nonce);
    out.extend_from_slice(&encode_optional_addr(request.dialed_addr)?);
    out.extend_from_slice(&encode_optional_addr(request.initiator_addr)?);
    out.extend_from_slice(&request.invite_fact_id);
    out.extend_from_slice(&request.bootstrap_hash);
    out.extend_from_slice(&request.invite_secret_fact_id);
    out.extend_from_slice(&request.initiator_ephemeral_secret_fact_id);
    out.extend_from_slice(&request.initiator_ephemeral_public_key);
    Ok(out)
}

pub fn endpoint_signing_transcript(request: &ConnectionRequestFact) -> Result<Vec<u8>, String> {
    if request.mode != REQUEST_MODE_MEMBERSHIP {
        return Err("membership request transcript requires membership mode".to_string());
    }
    let mut out = Vec::new();
    out.extend_from_slice(MEMBERSHIP_TRANSCRIPT_LABEL);
    out.push(request.mode);
    out.extend_from_slice(&request.from_endpoint);
    out.extend_from_slice(&request.to_endpoint);
    out.extend_from_slice(&request.nonce);
    out.extend_from_slice(&encode_optional_addr(request.dialed_addr)?);
    out.extend_from_slice(&encode_optional_addr(request.initiator_addr)?);
    out.extend_from_slice(&request.initiator_endpoint_shared_id);
    out.extend_from_slice(&request.initiator_ephemeral_secret_fact_id);
    out.extend_from_slice(&request.initiator_ephemeral_public_key);
    Ok(out)
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
        &bootstrap_signing_transcript(request)?,
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
        &endpoint_signing_transcript(request)?,
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
        &bootstrap_signing_transcript(request)?,
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
        &endpoint_signing_transcript(request)?,
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
