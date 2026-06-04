use crate::core::wire;
use crate::protocol::connection::bootstrap_request::create::{
    decode_optional_addr, encode_optional_addr, ADDR_BLOCK_BYTES,
};
use crate::protocol::connection::bootstrap_response::{layout as response_layout, transit};

use super::fact::BootstrapResponseSentFact;

pub const TYPE_BOOTSTRAP_RESPONSE_SENT: u8 = 181;
pub const FACT_BYTES: usize = 1
    + 32
    + 32
    + 32
    + ADDR_BLOCK_BYTES
    + response_layout::FACT_BYTES
    + transit::SEALED_CONNECTION_RESPONSE_BYTES
    + 8;

pub fn encode_fact(fact: &BootstrapResponseSentFact) -> Result<Vec<u8>, String> {
    transit::validate_sealed_response_frame(&fact.sealed_response_bytes)?;
    let response_bytes = response_layout::encode_fact(&fact.response)?;
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_BOOTSTRAP_RESPONSE_SENT, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.response_id);
    out[33..65].copy_from_slice(&fact.request_id);
    out[65..97].copy_from_slice(&fact.responder_ephemeral_secret_fact_id);
    out[97..97 + ADDR_BLOCK_BYTES].copy_from_slice(&encode_optional_addr(Some(fact.peer_addr))?);
    let mut cursor = 97 + ADDR_BLOCK_BYTES;
    out[cursor..cursor + response_layout::FACT_BYTES].copy_from_slice(&response_bytes);
    cursor += response_layout::FACT_BYTES;
    out[cursor..cursor + transit::SEALED_CONNECTION_RESPONSE_BYTES]
        .copy_from_slice(&fact.sealed_response_bytes);
    cursor += transit::SEALED_CONNECTION_RESPONSE_BYTES;
    wire::put_u64be(fact.created_at_ms, &mut out[cursor..cursor + 8]).map_err(wire_err)?;
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<BootstrapResponseSentFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
    if wire::take_u8(&bytes[0..1]).map_err(wire_err)? != TYPE_BOOTSTRAP_RESPONSE_SENT {
        return Err("expected bootstrap_response_sent fact".to_string());
    }
    let mut response_id = [0; 32];
    response_id.copy_from_slice(&bytes[1..33]);
    let mut request_id = [0; 32];
    request_id.copy_from_slice(&bytes[33..65]);
    let mut responder_ephemeral_secret_fact_id = [0; 32];
    responder_ephemeral_secret_fact_id.copy_from_slice(&bytes[65..97]);
    let mut addr_bytes = [0; ADDR_BLOCK_BYTES];
    addr_bytes.copy_from_slice(&bytes[97..97 + ADDR_BLOCK_BYTES]);
    let peer_addr = decode_optional_addr(&addr_bytes)?
        .ok_or_else(|| "bootstrap_response_sent peer address is missing".to_string())?;
    let mut cursor = 97 + ADDR_BLOCK_BYTES;
    let response =
        response_layout::decode_fact(&bytes[cursor..cursor + response_layout::FACT_BYTES])?;
    cursor += response_layout::FACT_BYTES;
    let mut sealed_response_bytes = [0u8; transit::SEALED_CONNECTION_RESPONSE_BYTES];
    sealed_response_bytes
        .copy_from_slice(&bytes[cursor..cursor + transit::SEALED_CONNECTION_RESPONSE_BYTES]);
    transit::validate_sealed_response_frame(&sealed_response_bytes)?;
    cursor += transit::SEALED_CONNECTION_RESPONSE_BYTES;
    let created_at_ms = wire::take_u64be(&bytes[cursor..cursor + 8]).map_err(wire_err)?;
    Ok(BootstrapResponseSentFact {
        response_id,
        request_id,
        responder_ephemeral_secret_fact_id,
        peer_addr,
        response,
        sealed_response_bytes,
        created_at_ms,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use crate::protocol::connection::bootstrap_response::fact::BootstrapResponseFact;

    use super::*;

    fn sealed_response_bytes() -> [u8; transit::SEALED_CONNECTION_RESPONSE_BYTES] {
        let mut bytes = [0u8; transit::SEALED_CONNECTION_RESPONSE_BYTES];
        bytes[0] = transit::TYPE_SEALED_CONNECTION_RESPONSE;
        bytes[1] = 1;
        bytes
    }

    fn response() -> BootstrapResponseFact {
        BootstrapResponseFact {
            from_endpoint: [1; 32],
            to_endpoint: [2; 32],
            request_id: [3; 32],
            invite_secret_fact_id: [4; 32],
            initiator_ephemeral_secret_fact_id: [5; 32],
            responder_ephemeral_secret_fact_id: [6; 32],
            responder_ephemeral_public_key: [7; 32],
            handshake_hash: [8; 32],
            connection_secret: [9; 32],
        }
    }

    fn fact() -> BootstrapResponseSentFact {
        BootstrapResponseSentFact {
            response_id: [10; 32],
            request_id: [3; 32],
            responder_ephemeral_secret_fact_id: [6; 32],
            peer_addr: "127.0.0.1:4401".parse().expect("socket addr"),
            response: response(),
            sealed_response_bytes: sealed_response_bytes(),
            created_at_ms: 11,
        }
    }

    #[test]
    fn bootstrap_response_sent_roundtrip_fixed_width() {
        let bytes = encode_fact(&fact()).expect("encode");
        assert_eq!(bytes.len(), FACT_BYTES);
        assert_eq!(decode_fact(&bytes).expect("decode"), fact());
    }
}
