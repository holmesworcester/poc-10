//! Canonical byte encoding for unified connection facts.
//!
//! This file owns deterministic connection bytes: the fact tag, fixed plaintext
//! field order and widths, the sealing transcript that turns a connection
//! plaintext into its sealed network envelope, and the public handshake transcript
//! used by both authoring and authentication. It does not open, authenticate, or
//! inspect context.
//!
//! The sealed bytes are the connection fact bytes and therefore the connection
//! id. The encrypted plaintext contains the connection secret and route
//! addresses; the header contains only metadata needed to open and match
//! context.

use std::net::SocketAddr;

use crate::core::crypto::{
    self, x25519_diffie_hellman, X25519PrivateKey, XChaCha20Poly1305Nonce,
    XCHACHA20_POLY1305_NONCE_BYTES, XCHACHA20_POLY1305_TAG_BYTES,
};
use crate::protocol::auth::endpoint::fact::EndpointFact;
use crate::protocol::auth::invite_secret::fact::InviteSecretFact;
use crate::protocol::connection::ephemeral_secret::fact::ConnectionEphemeralSecretFact;
use crate::protocol::connection::request::encode::{encode_optional_addr, ADDR_BLOCK_BYTES};
use crate::protocol::connection::request::fact::{
    ConnectionRequestFact, REQUEST_MODE_BOOTSTRAP, REQUEST_MODE_MEMBERSHIP,
};

use super::fact::ConnectionFact;

pub const TYPE_CONNECTION: u8 = 49;
pub(crate) const SEAL_VERSION: u8 = 1;
pub(crate) const CONNECTION_PURPOSE: &[u8] = b"topo-sealed-connection-v2";
pub(crate) const SEALED_HEADER_BYTES: usize = 1 + 1 + 32 + 32 + 32 + XCHACHA20_POLY1305_NONCE_BYTES;
const BOOTSTRAP_HANDSHAKE_PURPOSE: &[u8] = b"topo-connection-bootstrap-handshake-v2";
const MEMBERSHIP_HANDSHAKE_PURPOSE: &[u8] = b"topo-connection-membership-handshake-v2";
const CONNECTION_SECRET_PURPOSE: &[u8] = b"topo-connection-secret-v2";
const TRANSCRIPT_LABEL: &[u8] = b"topo-connection-handshake-transcript-v2";

pub const PLAINTEXT_FACT_BYTES: usize = 1 // tag
    + 32 // from_endpoint
    + 32 // to_endpoint
    + 32 // request_id
    + ADDR_BLOCK_BYTES // responder_addr
    + ADDR_BLOCK_BYTES // initiator_addr
    + 32 // initiator_ephemeral_secret_fact_id
    + 32 // responder_ephemeral_secret_fact_id
    + 32 // responder_ephemeral_public_key
    + 32 // handshake_hash
    + 32; // connection_secret
pub const FACT_BYTES: usize = PLAINTEXT_FACT_BYTES;
pub const SEALED_FACT_BYTES: usize =
    SEALED_HEADER_BYTES + PLAINTEXT_FACT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HandshakeMaterial {
    pub handshake_hash: [u8; 32],
    pub connection_secret: [u8; 32],
}

pub fn encode_fact(fact: &ConnectionFact) -> Result<Vec<u8>, String> {
    encode_plaintext(fact)
}

pub fn encode_plaintext(fact: &ConnectionFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; PLAINTEXT_FACT_BYTES];
    out[0] = TYPE_CONNECTION;
    out[1..33].copy_from_slice(&fact.from_endpoint);
    out[33..65].copy_from_slice(&fact.to_endpoint);
    out[65..97].copy_from_slice(&fact.request_id);
    let mut cursor = 97;
    out[cursor..cursor + ADDR_BLOCK_BYTES]
        .copy_from_slice(&encode_optional_addr(fact.responder_addr)?);
    cursor += ADDR_BLOCK_BYTES;
    out[cursor..cursor + ADDR_BLOCK_BYTES]
        .copy_from_slice(&encode_optional_addr(fact.initiator_addr)?);
    cursor += ADDR_BLOCK_BYTES;
    out[cursor..cursor + 32].copy_from_slice(&fact.initiator_ephemeral_secret_fact_id);
    cursor += 32;
    out[cursor..cursor + 32].copy_from_slice(&fact.responder_ephemeral_secret_fact_id);
    cursor += 32;
    out[cursor..cursor + 32].copy_from_slice(&fact.responder_ephemeral_public_key);
    cursor += 32;
    out[cursor..cursor + 32].copy_from_slice(&fact.handshake_hash);
    cursor += 32;
    out[cursor..cursor + 32].copy_from_slice(&fact.connection_secret);
    Ok(out)
}

pub fn seal_fact(
    connection: &ConnectionFact,
    responder_ephemeral_private_key: &X25519PrivateKey,
) -> Result<Vec<u8>, String> {
    seal_fact_with_nonce(
        connection,
        responder_ephemeral_private_key,
        crypto::random_xchacha20poly1305_nonce(),
    )
}

pub fn seal_fact_with_nonce(
    connection: &ConnectionFact,
    responder_ephemeral_private_key: &X25519PrivateKey,
    nonce: XChaCha20Poly1305Nonce,
) -> Result<Vec<u8>, String> {
    if crypto::x25519_public_key(responder_ephemeral_private_key)
        != connection.responder_ephemeral_public_key
    {
        return Err("sealed connection ephemeral key does not match connection".to_string());
    }
    let plaintext = encode_plaintext(connection)?;
    let header = sealed_header(
        connection.responder_ephemeral_public_key,
        connection.to_endpoint,
        connection.request_id,
        nonce,
    );
    let ciphertext = crypto::x25519_xchacha20poly1305_encrypt(
        responder_ephemeral_private_key,
        &connection.to_endpoint,
        CONNECTION_PURPOSE,
        &header,
        &nonce,
        &plaintext,
    )?;
    if ciphertext.len() != PLAINTEXT_FACT_BYTES + XCHACHA20_POLY1305_TAG_BYTES {
        return Err("sealed connection ciphertext length mismatch".to_string());
    }
    let mut out = Vec::with_capacity(SEALED_FACT_BYTES);
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    Ok(out)
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

pub fn responder_material(
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

fn sealed_header(
    responder_ephemeral_public_key: [u8; 32],
    to_endpoint: [u8; 32],
    request_id: [u8; 32],
    nonce: XChaCha20Poly1305Nonce,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(SEALED_HEADER_BYTES);
    out.push(TYPE_CONNECTION);
    out.push(SEAL_VERSION);
    out.extend_from_slice(&responder_ephemeral_public_key);
    out.extend_from_slice(&to_endpoint);
    out.extend_from_slice(&request_id);
    out.extend_from_slice(&nonce);
    out
}
