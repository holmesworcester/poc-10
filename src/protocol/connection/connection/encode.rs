//! Canonical byte encoding for unified connection facts.
//!
//! This file owns byte construction only: the fact tag, fixed plaintext field
//! order and widths, and the sealing transcript that turns a connection plaintext
//! into its sealed network envelope. It does not open, authenticate, or inspect
//! context.
//!
//! The sealed bytes are the connection fact bytes and therefore the connection
//! id. The encrypted plaintext contains the connection secret and route
//! addresses; the header contains only metadata needed to open and match
//! context.

use crate::core::crypto::{
    self, X25519PrivateKey, XChaCha20Poly1305Nonce, XCHACHA20_POLY1305_NONCE_BYTES,
    XCHACHA20_POLY1305_TAG_BYTES,
};
use crate::protocol::connection::request::encode::{encode_optional_addr, ADDR_BLOCK_BYTES};

use super::fact::ConnectionFact;

pub const TYPE_CONNECTION: u8 = 49;
pub(crate) const SEAL_VERSION: u8 = 1;
pub(crate) const CONNECTION_PURPOSE: &[u8] = b"topo-sealed-connection-v2";
pub(crate) const SEALED_HEADER_BYTES: usize = 1 + 1 + 32 + 32 + 32 + XCHACHA20_POLY1305_NONCE_BYTES;

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
    if crypto::x25519_public_key(responder_ephemeral_private_key)
        != connection.responder_ephemeral_public_key
    {
        return Err("sealed connection ephemeral key does not match connection".to_string());
    }
    let plaintext = encode_plaintext(connection)?;
    let nonce = crypto::random_xchacha20poly1305_nonce();
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
