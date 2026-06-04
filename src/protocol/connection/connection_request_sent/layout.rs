use crate::core::wire;
use crate::protocol::connection::bootstrap_request::create::{
    decode_optional_addr, encode_optional_addr, ADDR_BLOCK_BYTES,
};
use crate::protocol::connection::connection_request::layout as request_layout;

use super::fact::ConnectionRequestSentFact;

pub const TYPE_CONNECTION_REQUEST_SENT: u8 = 174;
pub const FACT_BYTES: usize = 1
    + 32 // request_id
    + 32 // initiator_ephemeral_secret_fact_id
    + ADDR_BLOCK_BYTES
    + request_layout::PLAINTEXT_FACT_BYTES
    + request_layout::SEALED_FACT_BYTES
    + 8;

pub fn encode_fact(fact: &ConnectionRequestSentFact) -> Result<Vec<u8>, String> {
    request_layout::validate_sealed_fact(&fact.sealed_request_bytes)?;
    let request_bytes = request_layout::encode_plaintext(&fact.request)?;
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_CONNECTION_REQUEST_SENT, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.request_id);
    out[33..65].copy_from_slice(&fact.initiator_ephemeral_secret_fact_id);
    out[65..65 + ADDR_BLOCK_BYTES].copy_from_slice(&encode_optional_addr(Some(fact.peer_addr))?);
    let mut cursor = 65 + ADDR_BLOCK_BYTES;
    out[cursor..cursor + request_layout::PLAINTEXT_FACT_BYTES].copy_from_slice(&request_bytes);
    cursor += request_layout::PLAINTEXT_FACT_BYTES;
    out[cursor..cursor + request_layout::SEALED_FACT_BYTES]
        .copy_from_slice(&fact.sealed_request_bytes);
    cursor += request_layout::SEALED_FACT_BYTES;
    wire::put_u64be(fact.created_at_ms, &mut out[cursor..cursor + 8]).map_err(wire_err)?;
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionRequestSentFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_CONNECTION_REQUEST_SENT {
        return Err("expected connection_request_sent fact".to_string());
    }
    let mut request_id = [0; 32];
    request_id.copy_from_slice(&bytes[1..33]);
    let mut initiator_ephemeral_secret_fact_id = [0; 32];
    initiator_ephemeral_secret_fact_id.copy_from_slice(&bytes[33..65]);
    let mut addr_bytes = [0; ADDR_BLOCK_BYTES];
    addr_bytes.copy_from_slice(&bytes[65..65 + ADDR_BLOCK_BYTES]);
    let peer_addr = decode_optional_addr(&addr_bytes)?
        .ok_or_else(|| "connection_request_sent peer address is missing".to_string())?;
    let mut cursor = 65 + ADDR_BLOCK_BYTES;
    let request = request_layout::decode_plaintext(
        &bytes[cursor..cursor + request_layout::PLAINTEXT_FACT_BYTES],
    )?;
    cursor += request_layout::PLAINTEXT_FACT_BYTES;
    let mut sealed_request_bytes = [0u8; request_layout::SEALED_FACT_BYTES];
    sealed_request_bytes
        .copy_from_slice(&bytes[cursor..cursor + request_layout::SEALED_FACT_BYTES]);
    request_layout::validate_sealed_fact(&sealed_request_bytes)?;
    cursor += request_layout::SEALED_FACT_BYTES;
    let created_at_ms = wire::take_u64be(&bytes[cursor..cursor + 8]).map_err(wire_err)?;
    Ok(ConnectionRequestSentFact {
        request_id,
        initiator_ephemeral_secret_fact_id,
        peer_addr,
        request,
        sealed_request_bytes,
        created_at_ms,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use crate::protocol::connection::connection_request::fact::ConnectionRequestFact;

    use super::*;

    fn sealed_request_bytes() -> [u8; request_layout::SEALED_FACT_BYTES] {
        let mut bytes = [0u8; request_layout::SEALED_FACT_BYTES];
        bytes[0] = request_layout::TYPE_CONNECTION_REQUEST;
        bytes[1] = 1;
        bytes
    }

    fn request() -> ConnectionRequestFact {
        ConnectionRequestFact {
            from_endpoint: [1; 32],
            to_endpoint: [2; 32],
            nonce: [3; 32],
            initiator_endpoint_shared_id: [4; 32],
            initiator_ephemeral_secret_fact_id: [5; 32],
            initiator_ephemeral_public_key: [6; 32],
            endpoint_signature: [7; crate::core::crypto::ED25519_SIGNATURE_BYTES],
            from_listen_addr: None,
            to_listen_addr: None,
        }
    }

    fn fact() -> ConnectionRequestSentFact {
        ConnectionRequestSentFact {
            request_id: [8; 32],
            initiator_ephemeral_secret_fact_id: [5; 32],
            peer_addr: "127.0.0.1:4400".parse().expect("socket addr"),
            request: request(),
            sealed_request_bytes: sealed_request_bytes(),
            created_at_ms: 9,
        }
    }

    #[test]
    fn connection_request_sent_roundtrip_fixed_width() {
        let bytes = encode_fact(&fact()).expect("encode");
        assert_eq!(bytes.len(), FACT_BYTES);
        assert_eq!(decode_fact(&bytes).expect("decode"), fact());
    }
}
