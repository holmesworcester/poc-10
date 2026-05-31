//! Wire transport for connection-response facts.
//!
//! A connection response is sent on the wire before established frames exist, so
//! its canonical fact bytes are sealed for transit rather than wrapped in a
//! separate envelope fact. Sealing encrypts the response bytes
//! responder-ephemeral → initiator-endpoint; opening recovers the identical
//! canonical bytes, admitted as the durable `connection_response` fact. The seal
//! header is transport-only and never part of the fact.
//!
//! Change this file for response wire-transport compatibility. The durable fact
//! layout lives in `layout.rs`; handshake derivation lives in `create.rs`;
//! admission lives in `project.rs`.

use crate::core::crypto::{
    self, X25519PrivateKey, XChaCha20Poly1305Nonce, XCHACHA20_POLY1305_NONCE_BYTES,
    XCHACHA20_POLY1305_TAG_BYTES,
};
use crate::protocol::auth::endpoint::fact::EndpointFact;

use super::layout;

/// First wire byte of a sealed connection-response frame.
pub const TYPE_SEALED_CONNECTION_RESPONSE: u8 = 47;

const VERSION: u8 = 1;
const RESPONSE_PURPOSE: &[u8] = b"topo-sealed-connection-response-v1";
const RESPONSE_HEADER_BYTES: usize = 1 + 1 + 32 + XCHACHA20_POLY1305_NONCE_BYTES;

pub const SEALED_CONNECTION_RESPONSE_BYTES: usize =
    RESPONSE_HEADER_BYTES + layout::FACT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;

/// Whether `frame` is a sealed connection-response frame (by its first byte).
pub fn is_sealed_response_frame(frame: &[u8]) -> bool {
    frame.first().copied() == Some(TYPE_SEALED_CONNECTION_RESPONSE)
}

pub fn validate_sealed_response_frame(frame: &[u8]) -> Result<(), String> {
    if frame.len() != SEALED_CONNECTION_RESPONSE_BYTES {
        return Err("sealed connection response has wrong length".to_string());
    }
    if frame[0] != TYPE_SEALED_CONNECTION_RESPONSE || frame[1] != VERSION {
        return Err("sealed connection response has unsupported header".to_string());
    }
    Ok(())
}

/// Seal a `connection_response` fact's canonical bytes for transit.
pub fn seal_connection_response(
    response_bytes: &[u8],
    responder_ephemeral_private_key: &X25519PrivateKey,
) -> Result<Vec<u8>, String> {
    let response = layout::decode_fact(response_bytes)?;
    if crypto::x25519_public_key(responder_ephemeral_private_key)
        != response.responder_ephemeral_public_key
    {
        return Err("sealed connection response ephemeral key does not match response".to_string());
    }

    let nonce = crypto::random_xchacha20poly1305_nonce();
    let header = response_header(response.responder_ephemeral_public_key, nonce);
    let ciphertext = crypto::x25519_xchacha20poly1305_encrypt(
        responder_ephemeral_private_key,
        &response.to_endpoint,
        RESPONSE_PURPOSE,
        &header,
        &nonce,
        response_bytes,
    )?;
    if ciphertext.len() != layout::FACT_BYTES + XCHACHA20_POLY1305_TAG_BYTES {
        return Err("sealed connection response ciphertext length mismatch".to_string());
    }

    let mut out = Vec::with_capacity(SEALED_CONNECTION_RESPONSE_BYTES);
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a sealed connection-response frame back to canonical response bytes.
pub fn open_connection_response(
    frame: &[u8],
    local_endpoint: &EndpointFact,
) -> Result<Vec<u8>, String> {
    validate_sealed_response_frame(frame)?;
    let mut responder_ephemeral_public_key = [0; 32];
    responder_ephemeral_public_key.copy_from_slice(&frame[2..34]);
    let nonce = nonce_from(&frame[34..58]);
    let header = &frame[..RESPONSE_HEADER_BYTES];
    let ciphertext = &frame[RESPONSE_HEADER_BYTES..];

    let plaintext = crypto::x25519_xchacha20poly1305_decrypt(
        &local_endpoint.secret,
        &responder_ephemeral_public_key,
        RESPONSE_PURPOSE,
        header,
        &nonce,
        ciphertext,
    )?;
    let response = layout::decode_fact(&plaintext)?;
    if response.to_endpoint != local_endpoint.endpoint {
        return Err("sealed connection response is addressed to another endpoint".to_string());
    }
    if response.responder_ephemeral_public_key != responder_ephemeral_public_key {
        return Err(
            "sealed connection response inner ephemeral key does not match header".to_string(),
        );
    }
    Ok(plaintext)
}

fn response_header(
    responder_ephemeral_public_key: [u8; 32],
    nonce: XChaCha20Poly1305Nonce,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(RESPONSE_HEADER_BYTES);
    out.push(TYPE_SEALED_CONNECTION_RESPONSE);
    out.push(VERSION);
    out.extend_from_slice(&responder_ephemeral_public_key);
    out.extend_from_slice(&nonce);
    out
}

fn nonce_from(bytes: &[u8]) -> XChaCha20Poly1305Nonce {
    let mut nonce = [0; XCHACHA20_POLY1305_NONCE_BYTES];
    nonce.copy_from_slice(bytes);
    nonce
}
