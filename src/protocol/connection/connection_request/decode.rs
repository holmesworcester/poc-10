//! Membership connection-request decoding: canonical wire bytes / `Fact` → typed
//! value.
//!
//! `decode_fact` checks tag, length, and field shape and produces the typed
//! `ConnectionRequestFact`. The `FactCodec` lives here so the read pipeline and
//! context provision decode a request owner through one entry. Signature
//! transcripts live in `encode.rs`; membership validation belongs in
//! `project.rs`.

use crate::core::crypto::ED25519_SIGNATURE_BYTES;
use crate::core::facts::Fact;
use crate::core::wire;
use crate::protocol::connection::bootstrap_request::create::{
    decode_optional_addr, ADDR_BLOCK_BYTES,
};

use super::encode::{FACT_BYTES, TYPE_CONNECTION_REQUEST};
use super::fact::ConnectionRequestFact;

pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionRequestFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
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

pub fn decode_fact_payload(bytes: &[u8]) -> Result<ConnectionRequestFact, String> {
    decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = ConnectionRequestFact;

    fn decode_fact(fact: &Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::connection::connection_request::encode::encode_fact;

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
        assert_eq!(bytes.len(), FACT_BYTES);
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
