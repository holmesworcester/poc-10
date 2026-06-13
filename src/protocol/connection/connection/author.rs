//! Unified connection construction helpers.

use std::net::SocketAddr;

use crate::core::crypto::{x25519_public_key, X25519PrivateKey, X25519PublicKey};
use crate::core::facts::{Fact, FactScope};
use crate::protocol::auth::endpoint::fact::EndpointFact;
use crate::protocol::auth::invite::fact::InviteSecretFact;
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
    let bytes = encode::seal_fact(&connection, &input.responder_ephemeral_private_key)?;
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
