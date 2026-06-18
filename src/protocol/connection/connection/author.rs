//! Unified connection construction helpers.

use std::net::SocketAddr;

use crate::core::crypto::{
    self, x25519_public_key, X25519PrivateKey, X25519PublicKey, XChaCha20Poly1305Nonce,
};
use crate::core::facts::{Fact, FactScope};
use crate::protocol::auth::endpoint::fact::EndpointFact;
use crate::protocol::auth::invite_secret::fact::InviteSecretFact;
use crate::protocol::connection::request::fact::ConnectionRequestFact;

use super::fact::ConnectionFact;
use super::{encode, project::decode};

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

pub struct DeterministicResponderOutput {
    pub ephemeral_private_key: X25519PrivateKey,
    pub seal_randomness: XChaCha20Poly1305Nonce,
}

pub fn deterministic_responder_output(
    endpoint_secret: &X25519PrivateKey,
    request_id: [u8; 32],
    authority_id: [u8; 32],
    receive_id: [u8; 32],
) -> DeterministicResponderOutput {
    let mut info = Vec::with_capacity(32 * 3);
    info.extend_from_slice(&request_id);
    info.extend_from_slice(&authority_id);
    info.extend_from_slice(&receive_id);

    let ephemeral_private_key = crypto::blake3_keyed_hash(
        endpoint_secret,
        b"topo:create-connection:responder-ephemeral:v1",
        &info,
    );
    let nonce_bytes = crypto::blake3_keyed_hash(
        endpoint_secret,
        b"topo:create-connection:seal-nonce:v1",
        &info,
    );
    let mut seal_randomness = [0u8; crypto::XCHACHA20_POLY1305_NONCE_BYTES];
    seal_randomness.copy_from_slice(&nonce_bytes[..crypto::XCHACHA20_POLY1305_NONCE_BYTES]);
    DeterministicResponderOutput {
        ephemeral_private_key,
        seal_randomness,
    }
}

pub fn build_responder_connection(
    input: BuildResponderConnection<'_>,
) -> Result<BuildResponderResult, String> {
    let seal_nonce = crate::core::crypto::random_xchacha20poly1305_nonce();
    build_responder_connection_with_seal_randomness(input, seal_nonce)
}

pub fn build_responder_connection_with_seal_randomness(
    input: BuildResponderConnection<'_>,
    seal_randomness: XChaCha20Poly1305Nonce,
) -> Result<BuildResponderResult, String> {
    let responder_ephemeral_public_key: X25519PublicKey =
        x25519_public_key(&input.responder_ephemeral_private_key);
    if input.request.to_endpoint != input.endpoint.endpoint {
        return Err("connection responder endpoint does not match request".to_string());
    }
    if input.request.from_endpoint == input.endpoint.endpoint {
        return Err("connection endpoints must differ".to_string());
    }
    let material = encode::responder_material(
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
    let bytes = encode::seal_fact_with_nonce(
        &connection,
        &input.responder_ephemeral_private_key,
        seal_randomness,
    )?;
    let fact = Fact::new(FactScope::Local, input.created_at_ms, bytes);
    Ok(BuildResponderResult { fact, connection })
}

pub fn fact_from_sealed_wire(bytes: &[u8], local_timestamp_ms: u64) -> Result<Fact, String> {
    decode::validate_sealed_fact(bytes)?;
    Ok(Fact::new(
        FactScope::Local,
        local_timestamp_ms,
        bytes.to_vec(),
    ))
}
