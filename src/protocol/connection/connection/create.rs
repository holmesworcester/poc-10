//! Unified connection construction helpers.

use std::net::SocketAddr;

use crate::core::crypto::{
    self, x25519_diffie_hellman, x25519_public_key, X25519PrivateKey, X25519PublicKey,
};
use crate::core::facts::{Fact, FactScope};
use crate::protocol::auth::endpoint::fact::EndpointFact;
use crate::protocol::auth::invite::fact::InviteSecretFact;
use crate::protocol::connection::ephemeral_secret::fact::ConnectionEphemeralSecretFact;
use crate::protocol::connection::request::create::encode_optional_addr;
use crate::protocol::connection::request::fact::{
    ConnectionRequestFact, REQUEST_MODE_BOOTSTRAP, REQUEST_MODE_MEMBERSHIP,
};

use super::fact::ConnectionFact;
use super::layout;

const BOOTSTRAP_HANDSHAKE_PURPOSE: &[u8] = b"topo-connection-bootstrap-handshake-v2";
const MEMBERSHIP_HANDSHAKE_PURPOSE: &[u8] = b"topo-connection-membership-handshake-v2";
const CONNECTION_SECRET_PURPOSE: &[u8] = b"topo-connection-secret-v2";
const TRANSCRIPT_LABEL: &[u8] = b"topo-connection-handshake-transcript-v2";

pub struct BuildResponderConnection<'a> {
    pub request_id: [u8; 32],
    pub request: &'a ConnectionRequestFact,
    pub invite: Option<&'a InviteSecretFact>,
    pub endpoint: &'a EndpointFact,
    pub responder_ephemeral_private_key: X25519PrivateKey,
    pub responder_ephemeral_secret_fact_id: [u8; 32],
    pub responder_addr: Option<SocketAddr>,
    pub initiator_addr: Option<SocketAddr>,
    pub created_at_ms: u64,
}

pub struct BuildResponderResult {
    pub fact: Fact,
    pub connection: ConnectionFact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeMaterial {
    pub handshake_hash: [u8; 32],
    pub connection_secret: [u8; 32],
}

pub fn build_responder_connection(
    input: BuildResponderConnection<'_>,
) -> Result<BuildResponderResult, String> {
    let responder_ephemeral_public_key: X25519PublicKey =
        x25519_public_key(&input.responder_ephemeral_private_key);
    if input.request.to_endpoint != input.endpoint.endpoint {
        return Err("connection responder endpoint does not match request".to_string());
    }
    if input.request.from_endpoint == input.endpoint.endpoint {
        return Err("connection endpoints must differ".to_string());
    }
    let material = responder_material(
        input.request_id,
        input.request,
        input.invite,
        input.endpoint,
        &input.responder_ephemeral_private_key,
        &responder_ephemeral_public_key,
        input.responder_addr,
        input.initiator_addr,
    )?;
    let connection = ConnectionFact {
        from_endpoint: input.endpoint.endpoint,
        to_endpoint: input.request.from_endpoint,
        request_id: input.request_id,
        responder_addr: input.responder_addr,
        initiator_addr: input.initiator_addr,
        initiator_ephemeral_secret_fact_id: input.request.initiator_ephemeral_secret_fact_id,
        responder_ephemeral_secret_fact_id: input.responder_ephemeral_secret_fact_id,
        responder_ephemeral_public_key,
        handshake_hash: material.handshake_hash,
        connection_secret: material.connection_secret,
    };
    let bytes = layout::seal_fact(&connection, &input.responder_ephemeral_private_key)?;
    let fact = Fact::new(FactScope::Local, input.created_at_ms, bytes);
    Ok(BuildResponderResult { fact, connection })
}

pub fn initiator_material(
    request_id: [u8; 32],
    request: &ConnectionRequestFact,
    invite: Option<&InviteSecretFact>,
    initiator_ephemeral: &ConnectionEphemeralSecretFact,
    responder_ephemeral_public_key: &[u8; 32],
    responder_addr: Option<SocketAddr>,
    initiator_addr: Option<SocketAddr>,
) -> Result<HandshakeMaterial, String> {
    if initiator_ephemeral.owner_endpoint != request.from_endpoint {
        return Err("connection initiator ephemeral owner does not match request".to_string());
    }
    if initiator_ephemeral.ephemeral_public_key != request.initiator_ephemeral_public_key {
        return Err("connection initiator ephemeral public key does not match request".to_string());
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
        responder_addr,
        initiator_addr,
        ee,
        es,
    )
}

fn responder_material(
    request_id: [u8; 32],
    request: &ConnectionRequestFact,
    invite: Option<&InviteSecretFact>,
    endpoint: &EndpointFact,
    responder_ephemeral_private_key: &X25519PrivateKey,
    responder_ephemeral_public_key: &[u8; 32],
    responder_addr: Option<SocketAddr>,
    initiator_addr: Option<SocketAddr>,
) -> Result<HandshakeMaterial, String> {
    let ee = x25519_diffie_hellman(
        responder_ephemeral_private_key,
        &request.initiator_ephemeral_public_key,
    );
    let es = x25519_diffie_hellman(&endpoint.secret, &request.initiator_ephemeral_public_key);
    material(
        request_id,
        request,
        invite,
        responder_ephemeral_public_key,
        responder_addr,
        initiator_addr,
        ee,
        es,
    )
}

pub fn public_handshake_hash(
    request_id: [u8; 32],
    request: &ConnectionRequestFact,
    responder_ephemeral_public_key: &[u8; 32],
    responder_addr: Option<SocketAddr>,
    initiator_addr: Option<SocketAddr>,
) -> Result<[u8; 32], String> {
    Ok(crypto::hash(&public_transcript(
        request_id,
        request,
        responder_ephemeral_public_key,
        responder_addr,
        initiator_addr,
    )?))
}

fn material(
    request_id: [u8; 32],
    request: &ConnectionRequestFact,
    invite: Option<&InviteSecretFact>,
    responder_ephemeral_public_key: &[u8; 32],
    responder_addr: Option<SocketAddr>,
    initiator_addr: Option<SocketAddr>,
    ee: [u8; 32],
    es: [u8; 32],
) -> Result<HandshakeMaterial, String> {
    let transcript = public_transcript(
        request_id,
        request,
        responder_ephemeral_public_key,
        responder_addr,
        initiator_addr,
    )?;
    let mut ikm = Vec::new();
    let purpose = match request.mode {
        REQUEST_MODE_BOOTSTRAP => {
            let invite =
                invite.ok_or_else(|| "bootstrap connection requires invite secret".to_string())?;
            if invite.bootstrap_hash != request.bootstrap_hash {
                return Err("connection invite secret does not match request".to_string());
            }
            ikm.extend_from_slice(&invite.bootstrap_secret);
            ikm.extend_from_slice(&request.bootstrap_hash);
            BOOTSTRAP_HANDSHAKE_PURPOSE
        }
        REQUEST_MODE_MEMBERSHIP => MEMBERSHIP_HANDSHAKE_PURPOSE,
        other => return Err(format!("unknown connection request mode {other}")),
    };
    ikm.extend_from_slice(&ee);
    ikm.extend_from_slice(&es);
    let response_key = crypto::hkdf_sha256_key(&ikm, purpose, &transcript)?;
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
    request: &ConnectionRequestFact,
    responder_ephemeral_public_key: &[u8; 32],
    responder_addr: Option<SocketAddr>,
    initiator_addr: Option<SocketAddr>,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    out.extend_from_slice(TRANSCRIPT_LABEL);
    out.extend_from_slice(&request_id);
    out.push(request.mode);
    out.extend_from_slice(&request.from_endpoint);
    out.extend_from_slice(&request.to_endpoint);
    out.extend_from_slice(&request.nonce);
    out.extend_from_slice(&encode_optional_addr(request.dialed_addr)?);
    out.extend_from_slice(&request.invite_fact_id);
    out.extend_from_slice(&request.bootstrap_hash);
    out.extend_from_slice(&request.invite_secret_fact_id);
    out.extend_from_slice(&request.invite_signature);
    out.extend_from_slice(&request.initiator_endpoint_shared_id);
    out.extend_from_slice(&request.endpoint_signature);
    out.extend_from_slice(&request.initiator_ephemeral_secret_fact_id);
    out.extend_from_slice(&request.initiator_ephemeral_public_key);
    out.extend_from_slice(responder_ephemeral_public_key);
    out.extend_from_slice(&encode_optional_addr(responder_addr)?);
    out.extend_from_slice(&encode_optional_addr(initiator_addr)?);
    Ok(out)
}
