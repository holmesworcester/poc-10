//! Stable bytes for membership connection-response facts.
//!
//! The semantic response plaintext is fixed width: tag byte followed by eight 32-byte fields for endpoints,
//! request/dependency ids, responder ephemeral public key, handshake hash, and
//! connection secret. There is no invite field on this path.
//! The network fact body is the sealed response: the same tag, a seal version,
//! the responder ephemeral public key, an AEAD nonce, and ciphertext over that
//! semantic plaintext. The sealed bytes are the fact bytes and therefore the
//! response id / connection id.
//!
//! Change this file for response wire compatibility only. Key-schedule
//! construction belongs in `create.rs`, and context validation in `project.rs`.

use crate::core::crypto::{
    self, X25519PrivateKey, XChaCha20Poly1305Nonce, XCHACHA20_POLY1305_NONCE_BYTES,
    XCHACHA20_POLY1305_TAG_BYTES,
};
use crate::core::wire;
use crate::protocol::auth::endpoint::fact::EndpointFact;

use super::fact::ConnectionResponseFact;

pub const TYPE_CONNECTION_RESPONSE: u8 = 49;
const SEAL_VERSION: u8 = 1;
const RESPONSE_PURPOSE: &[u8] = b"topo-sealed-membership-connection-response-v1";
const SEALED_HEADER_BYTES: usize = 1 + 1 + 32 + XCHACHA20_POLY1305_NONCE_BYTES;

pub const PLAINTEXT_FACT_BYTES: usize = 1 + 32 * 8;
pub const FACT_BYTES: usize = PLAINTEXT_FACT_BYTES;
pub const SEALED_FACT_BYTES: usize =
    SEALED_HEADER_BYTES + PLAINTEXT_FACT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;

pub fn encode_fact(fact: &ConnectionResponseFact) -> Result<Vec<u8>, String> {
    encode_plaintext(fact)
}

pub fn encode_plaintext(fact: &ConnectionResponseFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; PLAINTEXT_FACT_BYTES];
    wire::put_u8(TYPE_CONNECTION_RESPONSE, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.from_endpoint);
    out[33..65].copy_from_slice(&fact.to_endpoint);
    out[65..97].copy_from_slice(&fact.request_id);
    out[97..129].copy_from_slice(&fact.initiator_ephemeral_secret_fact_id);
    out[129..161].copy_from_slice(&fact.responder_ephemeral_secret_fact_id);
    out[161..193].copy_from_slice(&fact.responder_ephemeral_public_key);
    out[193..225].copy_from_slice(&fact.handshake_hash);
    out[225..257].copy_from_slice(&fact.connection_secret);
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionResponseFact, String> {
    decode_plaintext(bytes)
}

pub fn decode_plaintext(bytes: &[u8]) -> Result<ConnectionResponseFact, String> {
    wire::expect_len(bytes, PLAINTEXT_FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_CONNECTION_RESPONSE {
        return Err("expected membership connection response fact".to_string());
    }
    let mut from_endpoint = [0; 32];
    from_endpoint.copy_from_slice(&bytes[1..33]);
    let mut to_endpoint = [0; 32];
    to_endpoint.copy_from_slice(&bytes[33..65]);
    let mut request_id = [0; 32];
    request_id.copy_from_slice(&bytes[65..97]);
    let mut initiator_ephemeral_secret_fact_id = [0; 32];
    initiator_ephemeral_secret_fact_id.copy_from_slice(&bytes[97..129]);
    let mut responder_ephemeral_secret_fact_id = [0; 32];
    responder_ephemeral_secret_fact_id.copy_from_slice(&bytes[129..161]);
    let mut responder_ephemeral_public_key = [0; 32];
    responder_ephemeral_public_key.copy_from_slice(&bytes[161..193]);
    let mut handshake_hash = [0; 32];
    handshake_hash.copy_from_slice(&bytes[193..225]);
    let mut connection_secret = [0; 32];
    connection_secret.copy_from_slice(&bytes[225..257]);
    Ok(ConnectionResponseFact {
        from_endpoint,
        to_endpoint,
        request_id,
        initiator_ephemeral_secret_fact_id,
        responder_ephemeral_secret_fact_id,
        responder_ephemeral_public_key,
        handshake_hash,
        connection_secret,
    })
}

pub fn is_sealed_fact(bytes: &[u8]) -> bool {
    bytes.first().copied() == Some(TYPE_CONNECTION_RESPONSE) && bytes.len() == SEALED_FACT_BYTES
}

pub fn seal_fact(
    response: &ConnectionResponseFact,
    responder_ephemeral_private_key: &X25519PrivateKey,
) -> Result<Vec<u8>, String> {
    if crypto::x25519_public_key(responder_ephemeral_private_key)
        != response.responder_ephemeral_public_key
    {
        return Err(
            "sealed membership connection response ephemeral key does not match response"
                .to_string(),
        );
    }
    let plaintext = encode_plaintext(response)?;
    let nonce = crypto::random_xchacha20poly1305_nonce();
    let header = sealed_header(response.responder_ephemeral_public_key, nonce);
    let ciphertext = crypto::x25519_xchacha20poly1305_encrypt(
        responder_ephemeral_private_key,
        &response.to_endpoint,
        RESPONSE_PURPOSE,
        &header,
        &nonce,
        &plaintext,
    )?;
    if ciphertext.len() != PLAINTEXT_FACT_BYTES + XCHACHA20_POLY1305_TAG_BYTES {
        return Err("sealed membership connection response ciphertext length mismatch".to_string());
    }
    let mut out = Vec::with_capacity(SEALED_FACT_BYTES);
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open_fact(
    bytes: &[u8],
    local_endpoint: &EndpointFact,
) -> Result<ConnectionResponseFact, String> {
    let plaintext = open_fact_bytes(bytes, local_endpoint)?;
    decode_plaintext(&plaintext)
}

pub fn open_fact_bytes(bytes: &[u8], local_endpoint: &EndpointFact) -> Result<Vec<u8>, String> {
    validate_sealed_fact(bytes)?;
    let mut responder_ephemeral_public_key = [0; 32];
    responder_ephemeral_public_key.copy_from_slice(&bytes[2..34]);
    let nonce = nonce_from(&bytes[34..58]);
    let header = &bytes[..SEALED_HEADER_BYTES];
    let ciphertext = &bytes[SEALED_HEADER_BYTES..];
    let plaintext = crypto::x25519_xchacha20poly1305_decrypt(
        &local_endpoint.secret,
        &responder_ephemeral_public_key,
        RESPONSE_PURPOSE,
        header,
        &nonce,
        ciphertext,
    )?;
    let response = decode_plaintext(&plaintext)?;
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

pub fn validate_sealed_fact(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() != SEALED_FACT_BYTES {
        return Err("sealed membership connection response has wrong length".to_string());
    }
    if bytes[0] != TYPE_CONNECTION_RESPONSE || bytes[1] != SEAL_VERSION {
        return Err("sealed membership connection response has unsupported header".to_string());
    }
    Ok(())
}

fn sealed_header(
    responder_ephemeral_public_key: [u8; 32],
    nonce: XChaCha20Poly1305Nonce,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(SEALED_HEADER_BYTES);
    out.push(TYPE_CONNECTION_RESPONSE);
    out.push(SEAL_VERSION);
    out.extend_from_slice(&responder_ephemeral_public_key);
    out.extend_from_slice(&nonce);
    out
}

fn nonce_from(bytes: &[u8]) -> XChaCha20Poly1305Nonce {
    let mut nonce = [0; XCHACHA20_POLY1305_NONCE_BYTES];
    nonce.copy_from_slice(bytes);
    nonce
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> ConnectionResponseFact {
        ConnectionResponseFact {
            from_endpoint: [1; 32],
            to_endpoint: [2; 32],
            request_id: [3; 32],
            initiator_ephemeral_secret_fact_id: [4; 32],
            responder_ephemeral_secret_fact_id: [5; 32],
            responder_ephemeral_public_key: [6; 32],
            handshake_hash: [7; 32],
            connection_secret: [8; 32],
        }
    }

    #[test]
    fn membership_response_roundtrips_fixed_width() {
        let bytes = encode_fact(&fact()).expect("encode");
        assert_eq!(bytes.len(), PLAINTEXT_FACT_BYTES);
        assert_eq!(decode_fact(&bytes).expect("decode"), fact());
    }

    #[test]
    fn rejects_wrong_tag_or_length() {
        let mut bytes = encode_fact(&fact()).expect("encode");
        bytes[0] = TYPE_CONNECTION_RESPONSE.wrapping_add(1);
        assert!(decode_fact(&bytes).is_err());

        let mut short = encode_fact(&fact()).expect("encode");
        short.pop();
        assert!(decode_fact(&short).is_err());
    }
}
