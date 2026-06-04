//! Membership connection-response construction helpers.
//!
//! This module owns the responder-side key schedule and canonical response fact
//! construction for the membership path. Given a validated request, the local
//! endpoint, and responder ephemeral material, it computes the handshake hash
//! and connection secret from Diffie-Hellman only — no invite material — then
//! returns the local `connection_response` fact.
//!
//! The helpers are pure constructors: no store reads, no projection, no socket
//! IO. Change this file for handshake transcript or key-schedule changes; change
//! `project.rs` for admission policy.

use crate::core::crypto::{
    self, x25519_diffie_hellman, x25519_public_key, X25519PrivateKey, X25519PublicKey,
};
use crate::core::facts::{Fact, FactScope};

use super::fact::ConnectionResponseFact;
use super::layout;
use crate::protocol::auth::endpoint::fact::EndpointFact;
use crate::protocol::connection::connection_request::fact::ConnectionRequestFact;
use crate::protocol::connection::ephemeral_secret::fact::ConnectionEphemeralSecretFact;

const HANDSHAKE_PURPOSE: &[u8] = b"topo-membership-connection-handshake-v1";
const CONNECTION_SECRET_PURPOSE: &[u8] = b"topo-membership-connection-secret-v1";
const TRANSCRIPT_LABEL: &[u8] = b"topo-membership-connection-handshake-v1";

pub struct BuildResponderResponse<'a> {
    pub request_id: [u8; 32],
    pub request: &'a ConnectionRequestFact,
    pub endpoint: &'a EndpointFact,
    pub responder_ephemeral_private_key: X25519PrivateKey,
    pub responder_ephemeral_secret_fact_id: [u8; 32],
    pub created_at_ms: u64,
}

pub struct BuildResponderResult {
    pub fact: Fact,
    pub response: ConnectionResponseFact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeMaterial {
    pub handshake_hash: [u8; 32],
    pub connection_secret: [u8; 32],
}

/// Compute the responder handshake schedule and emit the canonical
/// `connection_response` fact. Pure constructor: no IO, no store reads.
pub fn build_responder_response(
    input: BuildResponderResponse<'_>,
) -> Result<BuildResponderResult, String> {
    let BuildResponderResponse {
        request_id,
        request,
        endpoint,
        responder_ephemeral_private_key,
        responder_ephemeral_secret_fact_id,
        created_at_ms,
    } = input;

    if request.from_endpoint == endpoint.endpoint {
        return Err("membership connection_response endpoints must differ".to_string());
    }

    let responder_ephemeral_public_key: X25519PublicKey =
        x25519_public_key(&responder_ephemeral_private_key);

    let ee = x25519_diffie_hellman(
        &responder_ephemeral_private_key,
        &request.initiator_ephemeral_public_key,
    );
    let es = x25519_diffie_hellman(&endpoint.secret, &request.initiator_ephemeral_public_key);

    let material = material(request_id, request, &responder_ephemeral_public_key, ee, es);

    let response = ConnectionResponseFact {
        from_endpoint: endpoint.endpoint,
        to_endpoint: request.from_endpoint,
        request_id,
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
    request: &ConnectionRequestFact,
    initiator_ephemeral: &ConnectionEphemeralSecretFact,
    responder_ephemeral_public_key: &[u8; 32],
) -> Result<HandshakeMaterial, String> {
    if initiator_ephemeral.owner_endpoint != request.from_endpoint {
        return Err(
            "membership connection response initiator ephemeral owner does not match request"
                .to_string(),
        );
    }
    if initiator_ephemeral.ephemeral_public_key != request.initiator_ephemeral_public_key {
        return Err(
            "membership connection response initiator ephemeral public key does not match request"
                .to_string(),
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
    Ok(material(
        request_id,
        request,
        responder_ephemeral_public_key,
        ee,
        es,
    ))
}

pub fn public_handshake_hash(
    request_id: [u8; 32],
    request: &ConnectionRequestFact,
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
    request: &ConnectionRequestFact,
    responder_ephemeral_public_key: &[u8; 32],
    ee: [u8; 32],
    es: [u8; 32],
) -> HandshakeMaterial {
    let transcript = public_transcript(request_id, request, responder_ephemeral_public_key);
    // Diffie-Hellman only: ikm = ee || es. No invite material.
    let mut ikm = Vec::with_capacity(32 * 2);
    ikm.extend_from_slice(&ee);
    ikm.extend_from_slice(&es);
    let response_key = crypto::hkdf_sha256_key(&ikm, HANDSHAKE_PURPOSE, &transcript)
        .expect("membership handshake response key");
    let handshake_hash = crypto::hash(&transcript);
    let connection_secret =
        crypto::hkdf_sha256_key(&response_key, CONNECTION_SECRET_PURPOSE, &handshake_hash)
            .expect("membership handshake connection secret");
    HandshakeMaterial {
        handshake_hash,
        connection_secret,
    }
}

fn public_transcript(
    request_id: [u8; 32],
    request: &ConnectionRequestFact,
    responder_ephemeral_public_key: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(TRANSCRIPT_LABEL.len() + 32 * 8);
    out.extend_from_slice(TRANSCRIPT_LABEL);
    out.extend_from_slice(&request_id);
    out.extend_from_slice(&request.from_endpoint);
    out.extend_from_slice(&request.to_endpoint);
    out.extend_from_slice(&request.nonce);
    out.extend_from_slice(&request.initiator_endpoint_shared_id);
    out.extend_from_slice(&request.initiator_ephemeral_public_key);
    out.extend_from_slice(responder_ephemeral_public_key);
    out
}
