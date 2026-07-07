//! Connection-handshake wire transport (membership pair).
//!
//! A membership connection request or response is sent on the wire before any
//! established connection secret exists, so the connection transport seals the
//! canonical plaintext fact bytes for transit and opens them back to the
//! identical canonical bytes on arrival. The recovered bytes are then admitted
//! as the durable plaintext `connection_request` / `connection_response` fact.
//!
//! This is the transport layer, not a fact role file: sealing/opening a fact for
//! the wire is the connection carrier's job, exactly like an established frame.
//! The seal header is transport-only and never part of the fact. Keep the
//! plaintext fact layout in each family's `encode`/`decode`; keep admission in
//! the family `project`.

use crate::core::crypto::{
    self, X25519PrivateKey, XChaCha20Poly1305Nonce, XCHACHA20_POLY1305_NONCE_BYTES,
    XCHACHA20_POLY1305_TAG_BYTES,
};
use crate::protocol::auth::endpoint::fact::EndpointFact;
use crate::protocol::connection::connection_request::decode as request_decode;
use crate::protocol::connection::connection_request::encode as request_encode;
use crate::protocol::connection::connection_response::decode as response_decode;
use crate::protocol::connection::connection_response::encode as response_encode;

const VERSION: u8 = 1;

// ---------------------------------------------------------------------------
// Membership connection request.
// ---------------------------------------------------------------------------

/// First wire byte of a sealed membership connection-request frame.
pub const TYPE_SEALED_CONNECTION_REQUEST: u8 = 56;

const REQUEST_PURPOSE: &[u8] = b"topo-sealed-membership-connection-request-v1";
const REQUEST_HEADER_BYTES: usize = 1 + 1 + 32 + XCHACHA20_POLY1305_NONCE_BYTES;

pub const SEALED_CONNECTION_REQUEST_BYTES: usize =
    REQUEST_HEADER_BYTES + request_encode::FACT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;

/// Whether `frame` is a sealed membership connection-request frame.
pub fn is_sealed_request_frame(frame: &[u8]) -> bool {
    frame.first().copied() == Some(TYPE_SEALED_CONNECTION_REQUEST)
}

pub fn validate_sealed_request_frame(frame: &[u8]) -> Result<(), String> {
    if frame.len() != SEALED_CONNECTION_REQUEST_BYTES {
        return Err("sealed membership connection request has wrong length".to_string());
    }
    if frame[0] != TYPE_SEALED_CONNECTION_REQUEST || frame[1] != VERSION {
        return Err("sealed membership connection request has unsupported header".to_string());
    }
    Ok(())
}

/// Seal a `connection_request` fact's canonical bytes for transit.
pub fn seal_connection_request(
    request_bytes: &[u8],
    initiator_ephemeral_private_key: &X25519PrivateKey,
) -> Result<Vec<u8>, String> {
    let request = request_decode::decode_fact(request_bytes)?;
    if crypto::x25519_public_key(initiator_ephemeral_private_key)
        != request.initiator_ephemeral_public_key
    {
        return Err(
            "sealed membership connection request ephemeral key does not match request".to_string(),
        );
    }

    let nonce = crypto::random_xchacha20poly1305_nonce();
    let header = request_header(request.initiator_ephemeral_public_key, nonce);
    let ciphertext = crypto::x25519_xchacha20poly1305_encrypt(
        initiator_ephemeral_private_key,
        &request.to_endpoint,
        REQUEST_PURPOSE,
        &header,
        &nonce,
        request_bytes,
    )?;
    if ciphertext.len() != request_encode::FACT_BYTES + XCHACHA20_POLY1305_TAG_BYTES {
        return Err("sealed membership connection request ciphertext length mismatch".to_string());
    }

    let mut out = Vec::with_capacity(SEALED_CONNECTION_REQUEST_BYTES);
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a sealed membership connection-request frame back to canonical bytes.
pub fn open_connection_request(
    frame: &[u8],
    local_endpoint: &EndpointFact,
) -> Result<Vec<u8>, String> {
    validate_sealed_request_frame(frame)?;
    let mut initiator_ephemeral_public_key = [0; 32];
    initiator_ephemeral_public_key.copy_from_slice(&frame[2..34]);
    let nonce = nonce_from(&frame[34..58]);
    let header = &frame[..REQUEST_HEADER_BYTES];
    let ciphertext = &frame[REQUEST_HEADER_BYTES..];

    let plaintext = crypto::x25519_xchacha20poly1305_decrypt(
        &local_endpoint.secret,
        &initiator_ephemeral_public_key,
        REQUEST_PURPOSE,
        header,
        &nonce,
        ciphertext,
    )?;
    let request = request_decode::decode_fact(&plaintext)?;
    if request.to_endpoint != local_endpoint.endpoint {
        return Err(
            "sealed membership connection request is addressed to another endpoint".to_string(),
        );
    }
    if request.initiator_ephemeral_public_key != initiator_ephemeral_public_key {
        return Err(
            "sealed membership connection request inner ephemeral key does not match header"
                .to_string(),
        );
    }
    Ok(plaintext)
}

fn request_header(
    initiator_ephemeral_public_key: [u8; 32],
    nonce: XChaCha20Poly1305Nonce,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(REQUEST_HEADER_BYTES);
    out.push(TYPE_SEALED_CONNECTION_REQUEST);
    out.push(VERSION);
    out.extend_from_slice(&initiator_ephemeral_public_key);
    out.extend_from_slice(&nonce);
    out
}

// ---------------------------------------------------------------------------
// Membership connection response.
// ---------------------------------------------------------------------------

/// First wire byte of a sealed membership connection-response frame.
pub const TYPE_SEALED_CONNECTION_RESPONSE: u8 = 57;

const RESPONSE_PURPOSE: &[u8] = b"topo-sealed-membership-connection-response-v1";
const RESPONSE_HEADER_BYTES: usize = 1 + 1 + 32 + XCHACHA20_POLY1305_NONCE_BYTES;

pub const SEALED_CONNECTION_RESPONSE_BYTES: usize =
    RESPONSE_HEADER_BYTES + response_encode::FACT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;

/// Whether `frame` is a sealed membership connection-response frame.
pub fn is_sealed_response_frame(frame: &[u8]) -> bool {
    frame.first().copied() == Some(TYPE_SEALED_CONNECTION_RESPONSE)
}

pub fn validate_sealed_response_frame(frame: &[u8]) -> Result<(), String> {
    if frame.len() != SEALED_CONNECTION_RESPONSE_BYTES {
        return Err("sealed membership connection response has wrong length".to_string());
    }
    if frame[0] != TYPE_SEALED_CONNECTION_RESPONSE || frame[1] != VERSION {
        return Err("sealed membership connection response has unsupported header".to_string());
    }
    Ok(())
}

/// Seal a `connection_response` fact's canonical bytes for transit.
pub fn seal_connection_response(
    response_bytes: &[u8],
    responder_ephemeral_private_key: &X25519PrivateKey,
) -> Result<Vec<u8>, String> {
    let response = response_decode::decode_fact(response_bytes)?;
    if crypto::x25519_public_key(responder_ephemeral_private_key)
        != response.responder_ephemeral_public_key
    {
        return Err(
            "sealed membership connection response ephemeral key does not match response"
                .to_string(),
        );
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
    if ciphertext.len() != response_encode::FACT_BYTES + XCHACHA20_POLY1305_TAG_BYTES {
        return Err("sealed membership connection response ciphertext length mismatch".to_string());
    }

    let mut out = Vec::with_capacity(SEALED_CONNECTION_RESPONSE_BYTES);
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a sealed membership connection-response frame back to canonical bytes.
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
    let response = response_decode::decode_fact(&plaintext)?;
    if response.to_endpoint != local_endpoint.endpoint {
        return Err(
            "sealed membership connection response is addressed to another endpoint".to_string(),
        );
    }
    if response.responder_ephemeral_public_key != responder_ephemeral_public_key {
        return Err(
            "sealed membership connection response inner ephemeral key does not match header"
                .to_string(),
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
