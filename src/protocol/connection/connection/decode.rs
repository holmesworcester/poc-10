//! Byte decoding for unified connection facts.
//!
//! Decoding proves only the fixed plaintext layout and the canonical sealed
//! envelope shape (tag, version, length, header fields). Helpers here can open
//! sealed bytes once a caller has ephemeral/endpoint context; the id check,
//! opening decision, and handshake material proof live in `authenticate.rs`.

use crate::core::crypto::{self, XChaCha20Poly1305Nonce, XCHACHA20_POLY1305_NONCE_BYTES};
use crate::core::wire;
use crate::protocol::auth::endpoint::fact::EndpointFact;
use crate::protocol::connection::ephemeral_secret::fact::ConnectionEphemeralSecretFact;
use crate::protocol::connection::request::{
    decode::decode_optional_addr, encode::ADDR_BLOCK_BYTES,
};

use super::encode::{
    CONNECTION_PURPOSE, PLAINTEXT_FACT_BYTES, SEALED_FACT_BYTES, SEALED_HEADER_BYTES, SEAL_VERSION,
    TYPE_CONNECTION,
};
use super::fact::ConnectionFact;

/// Sealed connection envelope codec.
///
/// Decoding a connection fact proves only the canonical sealed layout. The id
/// check, opening decision, and handshake material proof are `authenticate.rs`
/// work, so the decoded payload is the unit envelope.
pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = ();

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        validate_sealed_fact(fact.body())
    }
}

pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionFact, String> {
    decode_plaintext(bytes)
}

pub fn decode_plaintext(bytes: &[u8]) -> Result<ConnectionFact, String> {
    wire::expect_len(bytes, PLAINTEXT_FACT_BYTES).map_err(wire_err)?;
    if bytes[0] != TYPE_CONNECTION {
        return Err("expected connection fact".to_string());
    }
    let mut from_endpoint = [0; 32];
    from_endpoint.copy_from_slice(&bytes[1..33]);
    let mut to_endpoint = [0; 32];
    to_endpoint.copy_from_slice(&bytes[33..65]);
    let mut request_id = [0; 32];
    request_id.copy_from_slice(&bytes[65..97]);
    let mut cursor = 97;
    let mut addr_bytes = [0u8; ADDR_BLOCK_BYTES];
    addr_bytes.copy_from_slice(&bytes[cursor..cursor + ADDR_BLOCK_BYTES]);
    let responder_addr = decode_optional_addr(&addr_bytes)?;
    cursor += ADDR_BLOCK_BYTES;
    addr_bytes.copy_from_slice(&bytes[cursor..cursor + ADDR_BLOCK_BYTES]);
    let initiator_addr = decode_optional_addr(&addr_bytes)?;
    cursor += ADDR_BLOCK_BYTES;
    let mut initiator_ephemeral_secret_fact_id = [0; 32];
    initiator_ephemeral_secret_fact_id.copy_from_slice(&bytes[cursor..cursor + 32]);
    cursor += 32;
    let mut responder_ephemeral_secret_fact_id = [0; 32];
    responder_ephemeral_secret_fact_id.copy_from_slice(&bytes[cursor..cursor + 32]);
    cursor += 32;
    let mut responder_ephemeral_public_key = [0; 32];
    responder_ephemeral_public_key.copy_from_slice(&bytes[cursor..cursor + 32]);
    cursor += 32;
    let mut handshake_hash = [0; 32];
    handshake_hash.copy_from_slice(&bytes[cursor..cursor + 32]);
    cursor += 32;
    let mut connection_secret = [0; 32];
    connection_secret.copy_from_slice(&bytes[cursor..cursor + 32]);
    Ok(ConnectionFact {
        from_endpoint,
        to_endpoint,
        request_id,
        responder_addr,
        initiator_addr,
        initiator_ephemeral_secret_fact_id,
        responder_ephemeral_secret_fact_id,
        responder_ephemeral_public_key,
        handshake_hash,
        connection_secret,
    })
}

pub fn is_sealed_fact(bytes: &[u8]) -> bool {
    bytes.first().copied() == Some(TYPE_CONNECTION) && bytes.len() == SEALED_FACT_BYTES
}

pub fn open_fact(bytes: &[u8], local_endpoint: &EndpointFact) -> Result<ConnectionFact, String> {
    let plaintext = open_fact_bytes(bytes, local_endpoint)?;
    decode_plaintext(&plaintext)
}

pub fn open_fact_bytes(bytes: &[u8], local_endpoint: &EndpointFact) -> Result<Vec<u8>, String> {
    validate_sealed_fact(bytes)?;
    let responder_ephemeral_public_key = connection_header_ephemeral_public_key(bytes)?;
    let to_endpoint = connection_header_to_endpoint(bytes)?;
    let nonce = nonce_from(&bytes[98..122]);
    let header = &bytes[..SEALED_HEADER_BYTES];
    let ciphertext = &bytes[SEALED_HEADER_BYTES..];
    let plaintext = crypto::x25519_xchacha20poly1305_decrypt(
        &local_endpoint.secret,
        &responder_ephemeral_public_key,
        CONNECTION_PURPOSE,
        header,
        &nonce,
        ciphertext,
    )?;
    let connection = decode_plaintext(&plaintext)?;
    if connection.to_endpoint != local_endpoint.endpoint || connection.to_endpoint != to_endpoint {
        return Err("sealed connection is addressed to another endpoint".to_string());
    }
    validate_header_match(bytes, &connection)?;
    Ok(plaintext)
}

pub fn open_fact_as_responder(
    bytes: &[u8],
    responder_ephemeral: &ConnectionEphemeralSecretFact,
) -> Result<ConnectionFact, String> {
    let plaintext = open_fact_bytes_as_responder(bytes, responder_ephemeral)?;
    decode_plaintext(&plaintext)
}

pub fn open_fact_bytes_as_responder(
    bytes: &[u8],
    responder_ephemeral: &ConnectionEphemeralSecretFact,
) -> Result<Vec<u8>, String> {
    validate_sealed_fact(bytes)?;
    let responder_ephemeral_public_key = connection_header_ephemeral_public_key(bytes)?;
    if responder_ephemeral.ephemeral_public_key != responder_ephemeral_public_key {
        return Err("sealed connection responder ephemeral does not match header".to_string());
    }
    let to_endpoint = connection_header_to_endpoint(bytes)?;
    let nonce = nonce_from(&bytes[98..122]);
    let header = &bytes[..SEALED_HEADER_BYTES];
    let ciphertext = &bytes[SEALED_HEADER_BYTES..];
    let plaintext = crypto::x25519_xchacha20poly1305_decrypt(
        &responder_ephemeral.ephemeral_private_key,
        &to_endpoint,
        CONNECTION_PURPOSE,
        header,
        &nonce,
        ciphertext,
    )?;
    let connection = decode_plaintext(&plaintext)?;
    if connection.from_endpoint != responder_ephemeral.owner_endpoint {
        return Err("sealed connection responder does not own connection".to_string());
    }
    validate_header_match(bytes, &connection)?;
    Ok(plaintext)
}

pub fn validate_sealed_fact(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() != SEALED_FACT_BYTES {
        return Err("sealed connection has wrong length".to_string());
    }
    if bytes[0] != TYPE_CONNECTION || bytes[1] != SEAL_VERSION {
        return Err("sealed connection has unsupported header".to_string());
    }
    Ok(())
}

pub fn connection_header_ephemeral_public_key(bytes: &[u8]) -> Result<[u8; 32], String> {
    validate_sealed_fact(bytes)?;
    let mut key = [0; 32];
    key.copy_from_slice(&bytes[2..34]);
    Ok(key)
}

pub fn connection_header_to_endpoint(bytes: &[u8]) -> Result<[u8; 32], String> {
    validate_sealed_fact(bytes)?;
    let mut key = [0; 32];
    key.copy_from_slice(&bytes[34..66]);
    Ok(key)
}

pub fn connection_header_request_id(bytes: &[u8]) -> Result<[u8; 32], String> {
    validate_sealed_fact(bytes)?;
    let mut key = [0; 32];
    key.copy_from_slice(&bytes[66..98]);
    Ok(key)
}

fn validate_header_match(bytes: &[u8], connection: &ConnectionFact) -> Result<(), String> {
    if connection.responder_ephemeral_public_key != connection_header_ephemeral_public_key(bytes)? {
        return Err("sealed connection inner ephemeral key does not match header".to_string());
    }
    if connection.to_endpoint != connection_header_to_endpoint(bytes)? {
        return Err("sealed connection inner endpoint does not match header".to_string());
    }
    if connection.request_id != connection_header_request_id(bytes)? {
        return Err("sealed connection inner request id does not match header".to_string());
    }
    Ok(())
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
    use crate::protocol::connection::connection::encode::{
        encode_fact, PLAINTEXT_FACT_BYTES, TYPE_CONNECTION,
    };

    use super::*;

    fn fact() -> ConnectionFact {
        ConnectionFact {
            from_endpoint: [1; 32],
            to_endpoint: [2; 32],
            request_id: [3; 32],
            responder_addr: Some("127.0.0.1:41002".parse().unwrap()),
            initiator_addr: Some("127.0.0.1:41001".parse().unwrap()),
            initiator_ephemeral_secret_fact_id: [4; 32],
            responder_ephemeral_secret_fact_id: [5; 32],
            responder_ephemeral_public_key: [6; 32],
            handshake_hash: [7; 32],
            connection_secret: [8; 32],
        }
    }

    #[test]
    fn connection_roundtrips_fixed_width() {
        let bytes = encode_fact(&fact()).expect("encode");
        assert_eq!(bytes.len(), PLAINTEXT_FACT_BYTES);
        assert_eq!(decode_fact(&bytes).expect("decode"), fact());
    }

    #[test]
    fn rejects_wrong_tag_or_length() {
        let mut bytes = encode_fact(&fact()).expect("encode");
        bytes[0] = TYPE_CONNECTION.wrapping_add(1);
        assert!(decode_fact(&bytes).is_err());

        let mut short = encode_fact(&fact()).expect("encode");
        short.pop();
        assert!(decode_fact(&short).is_err());
    }
}
