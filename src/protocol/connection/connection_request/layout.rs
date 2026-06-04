//! Stable bytes for membership connection-request facts.
//!
//! The semantic request plaintext is fixed width: tag, endpoint ids, nonce, initiator
//! endpoint_shared fact id, initiator ephemeral secret fact id, initiator
//! ephemeral public key, an endpoint signature, and two fixed listen-address
//! blocks. Address blocks reuse the bootstrap request encoding so absent and
//! present addresses occupy identical widths.
//! The network fact body is the sealed request: the same tag, a seal version,
//! the initiator ephemeral public key, an AEAD nonce, and ciphertext over the
//! semantic plaintext. The sealed bytes are the fact bytes and therefore the
//! request id.
//!
//! Change this file for membership-request wire compatibility only. Signature
//! transcript construction lives in `create.rs`; context and membership
//! validation belong in `project.rs`.

use crate::core::crypto::{
    self, Ed25519Signature, X25519PrivateKey, XChaCha20Poly1305Nonce, ED25519_SIGNATURE_BYTES,
    XCHACHA20_POLY1305_NONCE_BYTES, XCHACHA20_POLY1305_TAG_BYTES,
};
use crate::core::wire;
use crate::protocol::auth::endpoint::fact::EndpointFact;
use crate::protocol::connection::bootstrap_request::create::{
    decode_optional_addr, encode_optional_addr, ADDR_BLOCK_BYTES,
};

use super::fact::ConnectionRequestFact;

pub const TYPE_CONNECTION_REQUEST: u8 = 48;
const SEAL_VERSION: u8 = 1;
const REQUEST_PURPOSE: &[u8] = b"topo-sealed-membership-connection-request-v1";
const SEALED_HEADER_BYTES: usize = 1 + 1 + 32 + XCHACHA20_POLY1305_NONCE_BYTES;

pub const PLAINTEXT_FACT_BYTES: usize = 1
    + 32 // from_endpoint
    + 32 // to_endpoint
    + 32 // nonce
    + 32 // initiator_endpoint_shared_id
    + 32 // initiator_ephemeral_secret_fact_id
    + 32 // initiator_ephemeral_public_key
    + ED25519_SIGNATURE_BYTES
    + ADDR_BLOCK_BYTES
    + ADDR_BLOCK_BYTES;
pub const FACT_BYTES: usize = PLAINTEXT_FACT_BYTES;
pub const SEALED_FACT_BYTES: usize =
    SEALED_HEADER_BYTES + PLAINTEXT_FACT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;

pub fn encode_fact(fact: &ConnectionRequestFact) -> Result<Vec<u8>, String> {
    encode_plaintext(fact)
}

pub fn encode_plaintext(fact: &ConnectionRequestFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; PLAINTEXT_FACT_BYTES];
    wire::put_u8(TYPE_CONNECTION_REQUEST, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.from_endpoint);
    out[33..65].copy_from_slice(&fact.to_endpoint);
    out[65..97].copy_from_slice(&fact.nonce);
    out[97..129].copy_from_slice(&fact.initiator_endpoint_shared_id);
    out[129..161].copy_from_slice(&fact.initiator_ephemeral_secret_fact_id);
    out[161..193].copy_from_slice(&fact.initiator_ephemeral_public_key);
    let mut cursor = 193;
    out[cursor..cursor + ED25519_SIGNATURE_BYTES].copy_from_slice(&fact.endpoint_signature);
    cursor += ED25519_SIGNATURE_BYTES;
    let addr_bytes = encode_optional_addr(fact.from_listen_addr)?;
    out[cursor..cursor + ADDR_BLOCK_BYTES].copy_from_slice(&addr_bytes);
    cursor += ADDR_BLOCK_BYTES;
    let addr_bytes = encode_optional_addr(fact.to_listen_addr)?;
    out[cursor..cursor + ADDR_BLOCK_BYTES].copy_from_slice(&addr_bytes);
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionRequestFact, String> {
    decode_plaintext(bytes)
}

pub fn decode_plaintext(bytes: &[u8]) -> Result<ConnectionRequestFact, String> {
    wire::expect_len(bytes, PLAINTEXT_FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_CONNECTION_REQUEST {
        return Err("expected membership connection request fact".to_string());
    }
    let mut from_endpoint = [0; 32];
    from_endpoint.copy_from_slice(&bytes[1..33]);
    let mut to_endpoint = [0; 32];
    to_endpoint.copy_from_slice(&bytes[33..65]);
    let mut nonce = [0; 32];
    nonce.copy_from_slice(&bytes[65..97]);
    let mut initiator_endpoint_shared_id = [0; 32];
    initiator_endpoint_shared_id.copy_from_slice(&bytes[97..129]);
    let mut initiator_ephemeral_secret_fact_id = [0; 32];
    initiator_ephemeral_secret_fact_id.copy_from_slice(&bytes[129..161]);
    let mut initiator_ephemeral_public_key = [0; 32];
    initiator_ephemeral_public_key.copy_from_slice(&bytes[161..193]);
    let mut cursor = 193;
    let mut endpoint_signature = [0; ED25519_SIGNATURE_BYTES];
    endpoint_signature.copy_from_slice(&bytes[cursor..cursor + ED25519_SIGNATURE_BYTES]);
    cursor += ED25519_SIGNATURE_BYTES;
    let mut addr_bytes = [0u8; ADDR_BLOCK_BYTES];
    addr_bytes.copy_from_slice(&bytes[cursor..cursor + ADDR_BLOCK_BYTES]);
    let from_listen_addr = decode_optional_addr(&addr_bytes)?;
    cursor += ADDR_BLOCK_BYTES;
    addr_bytes.copy_from_slice(&bytes[cursor..cursor + ADDR_BLOCK_BYTES]);
    let to_listen_addr = decode_optional_addr(&addr_bytes)?;
    Ok(ConnectionRequestFact {
        from_endpoint,
        to_endpoint,
        nonce,
        initiator_endpoint_shared_id,
        initiator_ephemeral_secret_fact_id,
        initiator_ephemeral_public_key,
        endpoint_signature,
        from_listen_addr,
        to_listen_addr,
    })
}

pub fn is_sealed_fact(bytes: &[u8]) -> bool {
    bytes.first().copied() == Some(TYPE_CONNECTION_REQUEST) && bytes.len() == SEALED_FACT_BYTES
}

pub fn seal_fact(
    request: &ConnectionRequestFact,
    initiator_ephemeral_private_key: &X25519PrivateKey,
) -> Result<Vec<u8>, String> {
    if crypto::x25519_public_key(initiator_ephemeral_private_key)
        != request.initiator_ephemeral_public_key
    {
        return Err(
            "sealed membership connection request ephemeral key does not match request".to_string(),
        );
    }
    let plaintext = encode_plaintext(request)?;
    let nonce = crypto::random_xchacha20poly1305_nonce();
    let header = sealed_header(request.initiator_ephemeral_public_key, nonce);
    let ciphertext = crypto::x25519_xchacha20poly1305_encrypt(
        initiator_ephemeral_private_key,
        &request.to_endpoint,
        REQUEST_PURPOSE,
        &header,
        &nonce,
        &plaintext,
    )?;
    if ciphertext.len() != PLAINTEXT_FACT_BYTES + XCHACHA20_POLY1305_TAG_BYTES {
        return Err("sealed membership connection request ciphertext length mismatch".to_string());
    }
    let mut out = Vec::with_capacity(SEALED_FACT_BYTES);
    out.extend_from_slice(&header);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open_fact(
    bytes: &[u8],
    local_endpoint: &EndpointFact,
) -> Result<ConnectionRequestFact, String> {
    let plaintext = open_fact_bytes(bytes, local_endpoint)?;
    decode_plaintext(&plaintext)
}

pub fn open_fact_bytes(bytes: &[u8], local_endpoint: &EndpointFact) -> Result<Vec<u8>, String> {
    validate_sealed_fact(bytes)?;
    let mut initiator_ephemeral_public_key = [0; 32];
    initiator_ephemeral_public_key.copy_from_slice(&bytes[2..34]);
    let nonce = nonce_from(&bytes[34..58]);
    let header = &bytes[..SEALED_HEADER_BYTES];
    let ciphertext = &bytes[SEALED_HEADER_BYTES..];
    let plaintext = crypto::x25519_xchacha20poly1305_decrypt(
        &local_endpoint.secret,
        &initiator_ephemeral_public_key,
        REQUEST_PURPOSE,
        header,
        &nonce,
        ciphertext,
    )?;
    let request = decode_plaintext(&plaintext)?;
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

pub fn request_header_ephemeral_public_key(bytes: &[u8]) -> Result<[u8; 32], String> {
    validate_sealed_fact(bytes)?;
    let mut key = [0; 32];
    key.copy_from_slice(&bytes[2..34]);
    Ok(key)
}

pub fn validate_sealed_fact(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() != SEALED_FACT_BYTES {
        return Err("sealed membership connection request has wrong length".to_string());
    }
    if bytes[0] != TYPE_CONNECTION_REQUEST || bytes[1] != SEAL_VERSION {
        return Err("sealed membership connection request has unsupported header".to_string());
    }
    Ok(())
}

fn sealed_header(
    initiator_ephemeral_public_key: [u8; 32],
    nonce: XChaCha20Poly1305Nonce,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(SEALED_HEADER_BYTES);
    out.push(TYPE_CONNECTION_REQUEST);
    out.push(SEAL_VERSION);
    out.extend_from_slice(&initiator_ephemeral_public_key);
    out.extend_from_slice(&nonce);
    out
}

fn nonce_from(bytes: &[u8]) -> XChaCha20Poly1305Nonce {
    let mut nonce = [0; XCHACHA20_POLY1305_NONCE_BYTES];
    nonce.copy_from_slice(bytes);
    nonce
}

pub fn endpoint_signature_bytes(signature: &Ed25519Signature) -> &[u8] {
    signature
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> ConnectionRequestFact {
        ConnectionRequestFact {
            from_endpoint: [1; 32],
            to_endpoint: [2; 32],
            nonce: [3; 32],
            initiator_endpoint_shared_id: [4; 32],
            initiator_ephemeral_secret_fact_id: [5; 32],
            initiator_ephemeral_public_key: [6; 32],
            endpoint_signature: [7; ED25519_SIGNATURE_BYTES],
            from_listen_addr: None,
            to_listen_addr: None,
        }
    }

    #[test]
    fn membership_request_roundtrips_without_listen_addrs() {
        let bytes = encode_fact(&fact()).expect("encode");
        assert_eq!(bytes.len(), PLAINTEXT_FACT_BYTES);
        assert_eq!(decode_fact(&bytes).expect("decode"), fact());
    }

    #[test]
    fn membership_request_roundtrips_with_listen_addrs() {
        let mut request = fact();
        request.from_listen_addr = Some("127.0.0.1:55555".parse().expect("ipv4"));
        request.to_listen_addr = Some("[::1]:8081".parse().expect("ipv6"));
        let bytes = encode_fact(&request).expect("encode");
        assert_eq!(bytes.len(), FACT_BYTES);
        assert_eq!(decode_fact(&bytes).expect("decode"), request);
    }

    #[test]
    fn rejects_wrong_tag_or_length() {
        let mut bytes = encode_fact(&fact()).expect("encode");
        bytes[0] = TYPE_CONNECTION_REQUEST.wrapping_add(1);
        assert!(decode_fact(&bytes).is_err());

        let mut short = encode_fact(&fact()).expect("encode");
        short.pop();
        assert!(decode_fact(&short).is_err());
    }
}
