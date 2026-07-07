//! Membership connection-response decoding: canonical wire bytes / `Fact` → typed
//! value.
//!
//! `decode_fact` checks tag, length, and field shape and produces the typed
//! `ConnectionResponseFact`. The `FactCodec` lives here so the read pipeline and
//! context provision decode a response owner through one entry. Byte order lives
//! in `encode.rs`; admission belongs in `project.rs`.

use crate::core::facts::Fact;
use crate::core::wire;

use super::encode::{FACT_BYTES, TYPE_CONNECTION_RESPONSE};
use super::fact::ConnectionResponseFact;

pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionResponseFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
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

pub fn decode_fact_payload(bytes: &[u8]) -> Result<ConnectionResponseFact, String> {
    decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = ConnectionResponseFact;

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
    use crate::protocol::connection::connection_response::encode::encode_fact;

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
        assert_eq!(bytes.len(), FACT_BYTES);
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
