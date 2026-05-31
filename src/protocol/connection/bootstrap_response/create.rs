//! Connection-response construction helpers.
//!
//! This module owns the responder-side native key schedule and canonical
//! response fact construction. Given validated request, invite, endpoint, and
//! responder ephemeral material, it computes the handshake hash and connection
//! secret, then returns the local `connection::response` fact.
//!
//! The helpers are pure constructors: no store reads, no projection, no socket
//! IO. Callers must already have proved dependency consistency. Change this file
//! for handshake transcript or key-schedule changes; change `project.rs` for
//! admission policy.

use crate::core::crypto::{
    self, x25519_diffie_hellman, x25519_public_key, X25519PrivateKey, X25519PublicKey,
};
use crate::core::facts::{Fact, FactScope};

use super::fact::BootstrapResponseFact;
use super::layout;
use crate::protocol::auth::endpoint::fact::EndpointFact;
use crate::protocol::auth::invite::fact::InviteSecretFact;
use crate::protocol::connection::ephemeral_secret::fact::ConnectionEphemeralSecretFact;
use crate::protocol::connection::bootstrap_request::fact::BootstrapRequestFact;

const HANDSHAKE_PURPOSE: &[u8] = b"topo-connection-handshake-v1";
const CONNECTION_SECRET_PURPOSE: &[u8] = b"topo-connection-secret-v1";
const TRANSCRIPT_LABEL: &[u8] = b"topo-native-connection-handshake-v1";

/// Inputs to the responder native key schedule.
///
/// `request_id` is the fact id of the inbound `connection::request` fact;
/// `request` / `invite` / `endpoint` are the decoded dependency facts;
/// `responder_ephemeral_private_key` is the X25519 ephemeral for this side,
/// and `responder_ephemeral_secret_fact_id` pins which (future) ephemeral
/// fact the response will reference.
pub struct BuildResponderResponse<'a> {
    pub request_id: [u8; 32],
    pub request: &'a BootstrapRequestFact,
    pub invite: &'a InviteSecretFact,
    pub endpoint: &'a EndpointFact,
    pub responder_ephemeral_private_key: X25519PrivateKey,
    pub responder_ephemeral_secret_fact_id: [u8; 32],
    pub created_at_ms: u64,
}

/// Returned by `build_responder_response`: the response fact and the decoded
/// fact body (the latter is useful for tests and downstream callers that
/// want to read the connection secret without re-decoding).
pub struct BuildResponderResult {
    pub fact: Fact,
    pub response: BootstrapResponseFact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeMaterial {
    pub handshake_hash: [u8; 32],
    pub connection_secret: [u8; 32],
}

/// Compute the responder handshake schedule and emit the canonical
/// `connection::response` fact.
///
/// This is a pure constructor: no IO and no store reads. The caller has already
/// validated dependency cross-checks, including invite bootstrap hash and
/// endpoint ownership.
pub fn build_responder_response(
    input: BuildResponderResponse<'_>,
) -> Result<BuildResponderResult, String> {
    let BuildResponderResponse {
        request_id,
        request,
        invite,
        endpoint,
        responder_ephemeral_private_key,
        responder_ephemeral_secret_fact_id,
        created_at_ms,
    } = input;

    if request.from_endpoint == endpoint.endpoint {
        return Err("connection::response endpoints must differ".to_string());
    }

    let responder_ephemeral_public_key: X25519PublicKey =
        x25519_public_key(&responder_ephemeral_private_key);

    let ee = x25519_diffie_hellman(
        &responder_ephemeral_private_key,
        &request.initiator_ephemeral_public_key,
    );
    let es = x25519_diffie_hellman(&endpoint.secret, &request.initiator_ephemeral_public_key);

    let material = material(
        request_id,
        request,
        invite,
        &responder_ephemeral_public_key,
        ee,
        es,
    )?;

    let response = BootstrapResponseFact {
        from_endpoint: endpoint.endpoint,
        to_endpoint: request.from_endpoint,
        request_id,
        invite_secret_fact_id: request.invite_secret_fact_id,
        initiator_ephemeral_secret_fact_id: request.initiator_ephemeral_secret_fact_id,
        responder_ephemeral_secret_fact_id,
        responder_ephemeral_public_key,
        handshake_hash: material.handshake_hash,
        connection_secret: material.connection_secret,
    };
    let bytes = layout::encode_fact(&response)?;
    let fact = Fact::new(FactScope::Local, created_at_ms, bytes);
    Ok(BuildResponderResult { fact, response })
}

pub fn initiator_material(
    request_id: [u8; 32],
    request: &BootstrapRequestFact,
    invite: &InviteSecretFact,
    initiator_ephemeral: &ConnectionEphemeralSecretFact,
    responder_ephemeral_public_key: &[u8; 32],
) -> Result<HandshakeMaterial, String> {
    if initiator_ephemeral.owner_endpoint != request.from_endpoint {
        return Err(
            "connection response initiator ephemeral owner does not match request".to_string(),
        );
    }
    if initiator_ephemeral.ephemeral_public_key != request.initiator_ephemeral_public_key {
        return Err(
            "connection response initiator ephemeral public key does not match request".to_string(),
        );
    }
    let ee = x25519_diffie_hellman(
        &initiator_ephemeral.ephemeral_private_key,
        responder_ephemeral_public_key,
    );
    let es = x25519_diffie_hellman(
        &initiator_ephemeral.ephemeral_private_key,
        &request.to_endpoint,
    );
    material(
        request_id,
        request,
        invite,
        responder_ephemeral_public_key,
        ee,
        es,
    )
}

pub fn public_handshake_hash(
    request_id: [u8; 32],
    request: &BootstrapRequestFact,
    responder_ephemeral_public_key: &[u8; 32],
) -> [u8; 32] {
    crypto::hash(&public_transcript(
        request_id,
        request,
        responder_ephemeral_public_key,
    ))
}

fn material(
    request_id: [u8; 32],
    request: &BootstrapRequestFact,
    invite: &InviteSecretFact,
    responder_ephemeral_public_key: &[u8; 32],
    ee: [u8; 32],
    es: [u8; 32],
) -> Result<HandshakeMaterial, String> {
    if invite.bootstrap_hash != request.bootstrap_hash {
        return Err("connection handshake invite secret does not match request".to_string());
    }
    let transcript = public_transcript(request_id, request, responder_ephemeral_public_key);
    let mut ikm = Vec::with_capacity(32 * 4);
    ikm.extend_from_slice(&invite.bootstrap_secret);
    ikm.extend_from_slice(&ee);
    ikm.extend_from_slice(&es);
    ikm.extend_from_slice(&request.bootstrap_hash);
    let response_key = crypto::hkdf_sha256_key(&ikm, HANDSHAKE_PURPOSE, &transcript)?;
    let handshake_hash = crypto::hash(&transcript);
    let connection_secret =
        crypto::hkdf_sha256_key(&response_key, CONNECTION_SECRET_PURPOSE, &handshake_hash)?;
    Ok(HandshakeMaterial {
        handshake_hash,
        connection_secret,
    })
}

fn public_transcript(
    request_id: [u8; 32],
    request: &BootstrapRequestFact,
    responder_ephemeral_public_key: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(TRANSCRIPT_LABEL.len() + 32 * 10 + 64);
    out.extend_from_slice(TRANSCRIPT_LABEL);
    out.extend_from_slice(&request_id);
    out.extend_from_slice(&request.from_endpoint);
    out.extend_from_slice(&request.to_endpoint);
    out.extend_from_slice(&request.nonce);
    out.extend_from_slice(&request.invite_fact_id);
    out.extend_from_slice(&request.bootstrap_hash);
    out.extend_from_slice(&request.invite_signature);
    out.extend_from_slice(&request.invite_secret_fact_id);
    out.extend_from_slice(&request.initiator_ephemeral_secret_fact_id);
    out.extend_from_slice(&request.initiator_ephemeral_public_key);
    out.extend_from_slice(responder_ephemeral_public_key);
    out
}
