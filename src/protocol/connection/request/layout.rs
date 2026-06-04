//! Stable bytes for unified connection-request facts.
//!
//! The semantic request plaintext is fixed width for both bootstrap and
//! membership modes. The network fact body is the sealed request:
//! `tag || seal_version || initiator_ephemeral_public_key || to_endpoint || nonce ||
//! ciphertext`. The sealed bytes are the fact bytes and therefore the request id.

use crate::core::crypto::{
    self, Ed25519Signature, X25519PrivateKey, XChaCha20Poly1305Nonce, ED25519_SIGNATURE_BYTES,
    XCHACHA20_POLY1305_NONCE_BYTES, XCHACHA20_POLY1305_TAG_BYTES,
};
use crate::core::wire;
use crate::protocol::auth::endpoint::fact::EndpointFact;
use crate::protocol::connection::ephemeral_secret::fact::ConnectionEphemeralSecretFact;
use crate::protocol::connection::request::create::{
    decode_optional_addr, encode_optional_addr, ADDR_BLOCK_BYTES,
};

use super::fact::ConnectionRequestFact;

pub const TYPE_CONNECTION_REQUEST: u8 = 48;
const SEAL_VERSION: u8 = 1;
const REQUEST_PURPOSE: &[u8] = b"topo-sealed-connection-request-v2";
const SEALED_HEADER_BYTES: usize = 1 + 1 + 32 + 32 + XCHACHA20_POLY1305_NONCE_BYTES;

pub const PLAINTEXT_FACT_BYTES: usize = 1 // tag
    + 1 // mode
    + 32 // from_endpoint
    + 32 // to_endpoint
    + 32 // nonce
    + ADDR_BLOCK_BYTES // dialed_addr
    + ADDR_BLOCK_BYTES // initiator_addr
    + 32 // invite_fact_id
    + 32 // bootstrap_hash
    + 32 // invite_secret_fact_id
    + ED25519_SIGNATURE_BYTES // invite_signature
    + 32 // initiator_endpoint_shared_id
    + ED25519_SIGNATURE_BYTES // endpoint_signature
    + 32 // initiator_ephemeral_secret_fact_id
    + 32; // initiator_ephemeral_public_key
pub const FACT_BYTES: usize = PLAINTEXT_FACT_BYTES;
pub const SEALED_FACT_BYTES: usize =
    SEALED_HEADER_BYTES + PLAINTEXT_FACT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;

pub fn encode_fact(fact: &ConnectionRequestFact) -> Result<Vec<u8>, String> {
    encode_plaintext(fact)
}

pub fn encode_plaintext(fact: &ConnectionRequestFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; PLAINTEXT_FACT_BYTES];
    out[0] = TYPE_CONNECTION_REQUEST;
    out[1] = fact.mode;
    out[2..34].copy_from_slice(&fact.from_endpoint);
    out[34..66].copy_from_slice(&fact.to_endpoint);
    out[66..98].copy_from_slice(&fact.nonce);
    let mut cursor = 98;
    out[cursor..cursor + ADDR_BLOCK_BYTES]
        .copy_from_slice(&encode_optional_addr(fact.dialed_addr)?);
    cursor += ADDR_BLOCK_BYTES;
    out[cursor..cursor + ADDR_BLOCK_BYTES]
        .copy_from_slice(&encode_optional_addr(fact.initiator_addr)?);
    cursor += ADDR_BLOCK_BYTES;
    out[cursor..cursor + 32].copy_from_slice(&fact.invite_fact_id);
    cursor += 32;
    out[cursor..cursor + 32].copy_from_slice(&fact.bootstrap_hash);
    cursor += 32;
    out[cursor..cursor + 32].copy_from_slice(&fact.invite_secret_fact_id);
    cursor += 32;
    out[cursor..cursor + ED25519_SIGNATURE_BYTES].copy_from_slice(&fact.invite_signature);
    cursor += ED25519_SIGNATURE_BYTES;
    out[cursor..cursor + 32].copy_from_slice(&fact.initiator_endpoint_shared_id);
    cursor += 32;
    out[cursor..cursor + ED25519_SIGNATURE_BYTES].copy_from_slice(&fact.endpoint_signature);
    cursor += ED25519_SIGNATURE_BYTES;
    out[cursor..cursor + 32].copy_from_slice(&fact.initiator_ephemeral_secret_fact_id);
    cursor += 32;
    out[cursor..cursor + 32].copy_from_slice(&fact.initiator_ephemeral_public_key);
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionRequestFact, String> {
    decode_plaintext(bytes)
}

pub fn decode_plaintext(bytes: &[u8]) -> Result<ConnectionRequestFact, String> {
    wire::expect_len(bytes, PLAINTEXT_FACT_BYTES).map_err(wire_err)?;
    if bytes[0] != TYPE_CONNECTION_REQUEST {
        return Err("expected connection request fact".to_string());
    }
    let mode = bytes[1];
    let mut from_endpoint = [0; 32];
    from_endpoint.copy_from_slice(&bytes[2..34]);
    let mut to_endpoint = [0; 32];
    to_endpoint.copy_from_slice(&bytes[34..66]);
    let mut nonce = [0; 32];
    nonce.copy_from_slice(&bytes[66..98]);
    let mut cursor = 98;
    let mut addr_bytes = [0u8; ADDR_BLOCK_BYTES];
    addr_bytes.copy_from_slice(&bytes[cursor..cursor + ADDR_BLOCK_BYTES]);
    let dialed_addr = decode_optional_addr(&addr_bytes)?;
    cursor += ADDR_BLOCK_BYTES;
    addr_bytes.copy_from_slice(&bytes[cursor..cursor + ADDR_BLOCK_BYTES]);
    let initiator_addr = decode_optional_addr(&addr_bytes)?;
    cursor += ADDR_BLOCK_BYTES;
    let mut invite_fact_id = [0; 32];
    invite_fact_id.copy_from_slice(&bytes[cursor..cursor + 32]);
    cursor += 32;
    let mut bootstrap_hash = [0; 32];
    bootstrap_hash.copy_from_slice(&bytes[cursor..cursor + 32]);
    cursor += 32;
    let mut invite_secret_fact_id = [0; 32];
    invite_secret_fact_id.copy_from_slice(&bytes[cursor..cursor + 32]);
    cursor += 32;
    let mut invite_signature = [0; ED25519_SIGNATURE_BYTES];
    invite_signature.copy_from_slice(&bytes[cursor..cursor + ED25519_SIGNATURE_BYTES]);
    cursor += ED25519_SIGNATURE_BYTES;
    let mut initiator_endpoint_shared_id = [0; 32];
    initiator_endpoint_shared_id.copy_from_slice(&bytes[cursor..cursor + 32]);
    cursor += 32;
    let mut endpoint_signature = [0; ED25519_SIGNATURE_BYTES];
    endpoint_signature.copy_from_slice(&bytes[cursor..cursor + ED25519_SIGNATURE_BYTES]);
    cursor += ED25519_SIGNATURE_BYTES;
    let mut initiator_ephemeral_secret_fact_id = [0; 32];
    initiator_ephemeral_secret_fact_id.copy_from_slice(&bytes[cursor..cursor + 32]);
    cursor += 32;
    let mut initiator_ephemeral_public_key = [0; 32];
    initiator_ephemeral_public_key.copy_from_slice(&bytes[cursor..cursor + 32]);
    Ok(ConnectionRequestFact {
        mode,
        from_endpoint,
        to_endpoint,
        nonce,
        dialed_addr,
        initiator_addr,
        invite_fact_id,
        bootstrap_hash,
        invite_secret_fact_id,
        invite_signature,
        initiator_endpoint_shared_id,
        endpoint_signature,
        initiator_ephemeral_secret_fact_id,
        initiator_ephemeral_public_key,
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
        return Err("sealed connection request ephemeral key does not match request".to_string());
    }
    let plaintext = encode_plaintext(request)?;
    let nonce = crypto::random_xchacha20poly1305_nonce();
    let header = sealed_header(
        request.initiator_ephemeral_public_key,
        request.to_endpoint,
        nonce,
    );
    let ciphertext = crypto::x25519_xchacha20poly1305_encrypt(
        initiator_ephemeral_private_key,
        &request.to_endpoint,
        REQUEST_PURPOSE,
        &header,
        &nonce,
        &plaintext,
    )?;
    if ciphertext.len() != PLAINTEXT_FACT_BYTES + XCHACHA20_POLY1305_TAG_BYTES {
        return Err("sealed connection request ciphertext length mismatch".to_string());
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
    let initiator_ephemeral_public_key = request_header_ephemeral_public_key(bytes)?;
    let to_endpoint = request_header_to_endpoint(bytes)?;
    let nonce = nonce_from(&bytes[66..90]);
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
    if request.to_endpoint != local_endpoint.endpoint || request.to_endpoint != to_endpoint {
        return Err("sealed connection request is addressed to another endpoint".to_string());
    }
    if request.initiator_ephemeral_public_key != initiator_ephemeral_public_key {
        return Err(
            "sealed connection request inner ephemeral key does not match header".to_string(),
        );
    }
    Ok(plaintext)
}

pub fn open_fact_as_sender(
    bytes: &[u8],
    initiator_ephemeral: &ConnectionEphemeralSecretFact,
) -> Result<ConnectionRequestFact, String> {
    let plaintext = open_fact_bytes_as_sender(bytes, initiator_ephemeral)?;
    decode_plaintext(&plaintext)
}

pub fn open_fact_bytes_as_sender(
    bytes: &[u8],
    initiator_ephemeral: &ConnectionEphemeralSecretFact,
) -> Result<Vec<u8>, String> {
    validate_sealed_fact(bytes)?;
    let initiator_ephemeral_public_key = request_header_ephemeral_public_key(bytes)?;
    if initiator_ephemeral.ephemeral_public_key != initiator_ephemeral_public_key {
        return Err(
            "sealed connection request sender ephemeral key does not match header".to_string(),
        );
    }
    let to_endpoint = request_header_to_endpoint(bytes)?;
    let nonce = nonce_from(&bytes[66..90]);
    let header = &bytes[..SEALED_HEADER_BYTES];
    let ciphertext = &bytes[SEALED_HEADER_BYTES..];
    let plaintext = crypto::x25519_xchacha20poly1305_decrypt(
        &initiator_ephemeral.ephemeral_private_key,
        &to_endpoint,
        REQUEST_PURPOSE,
        header,
        &nonce,
        ciphertext,
    )?;
    let request = decode_plaintext(&plaintext)?;
    if request.to_endpoint != to_endpoint {
        return Err("sealed connection request inner endpoint does not match header".to_string());
    }
    if request.from_endpoint != initiator_ephemeral.owner_endpoint {
        return Err("sealed connection request sender does not own request".to_string());
    }
    if request.initiator_ephemeral_public_key != initiator_ephemeral.ephemeral_public_key {
        return Err(
            "sealed connection request inner ephemeral key does not match sender".to_string(),
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

pub fn request_header_to_endpoint(bytes: &[u8]) -> Result<[u8; 32], String> {
    validate_sealed_fact(bytes)?;
    let mut key = [0; 32];
    key.copy_from_slice(&bytes[34..66]);
    Ok(key)
}

pub fn validate_sealed_fact(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() != SEALED_FACT_BYTES {
        return Err("sealed connection request has wrong length".to_string());
    }
    if bytes[0] != TYPE_CONNECTION_REQUEST || bytes[1] != SEAL_VERSION {
        return Err("sealed connection request has unsupported header".to_string());
    }
    Ok(())
}

fn sealed_header(
    initiator_ephemeral_public_key: [u8; 32],
    to_endpoint: [u8; 32],
    nonce: XChaCha20Poly1305Nonce,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(SEALED_HEADER_BYTES);
    out.push(TYPE_CONNECTION_REQUEST);
    out.push(SEAL_VERSION);
    out.extend_from_slice(&initiator_ephemeral_public_key);
    out.extend_from_slice(&to_endpoint);
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
    use crate::core::crypto::ED25519_SIGNATURE_BYTES;
    use crate::protocol::connection::request::fact::{
        REQUEST_MODE_BOOTSTRAP, REQUEST_MODE_MEMBERSHIP,
    };

    use super::*;

    fn fact(mode: u8) -> ConnectionRequestFact {
        ConnectionRequestFact {
            mode,
            from_endpoint: [1; 32],
            to_endpoint: [2; 32],
            nonce: [3; 32],
            dialed_addr: Some("127.0.0.1:41001".parse().unwrap()),
            initiator_addr: Some("127.0.0.1:41000".parse().unwrap()),
            invite_fact_id: if mode == REQUEST_MODE_BOOTSTRAP {
                [4; 32]
            } else {
                [0; 32]
            },
            bootstrap_hash: if mode == REQUEST_MODE_BOOTSTRAP {
                [5; 32]
            } else {
                [0; 32]
            },
            invite_secret_fact_id: if mode == REQUEST_MODE_BOOTSTRAP {
                [6; 32]
            } else {
                [0; 32]
            },
            invite_signature: if mode == REQUEST_MODE_BOOTSTRAP {
                [7; ED25519_SIGNATURE_BYTES]
            } else {
                [0; ED25519_SIGNATURE_BYTES]
            },
            initiator_endpoint_shared_id: if mode == REQUEST_MODE_MEMBERSHIP {
                [8; 32]
            } else {
                [0; 32]
            },
            endpoint_signature: if mode == REQUEST_MODE_MEMBERSHIP {
                [9; ED25519_SIGNATURE_BYTES]
            } else {
                [0; ED25519_SIGNATURE_BYTES]
            },
            initiator_ephemeral_secret_fact_id: [10; 32],
            initiator_ephemeral_public_key: [11; 32],
        }
    }

    #[test]
    fn connection_request_roundtrips_fixed_width() {
        for mode in [REQUEST_MODE_BOOTSTRAP, REQUEST_MODE_MEMBERSHIP] {
            let bytes = encode_fact(&fact(mode)).expect("encode");
            assert_eq!(bytes.len(), PLAINTEXT_FACT_BYTES);
            assert_eq!(decode_fact(&bytes).expect("decode"), fact(mode));
        }
    }

    #[test]
    fn rejects_wrong_tag_or_length() {
        let mut bytes = encode_fact(&fact(REQUEST_MODE_MEMBERSHIP)).expect("encode");
        bytes[0] = TYPE_CONNECTION_REQUEST.wrapping_add(1);
        assert!(decode_fact(&bytes).is_err());

        let mut short = encode_fact(&fact(REQUEST_MODE_MEMBERSHIP)).expect("encode");
        short.pop();
        assert!(decode_fact(&short).is_err());
    }
}
