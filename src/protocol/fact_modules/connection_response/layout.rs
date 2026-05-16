//! Connection-response fact layout.
//!
//! Fixed-width body: tag byte followed by nine 32-byte ids (the two endpoints,
//! the request id, three dependency edges, the responder ephemeral public key,
//! the handshake hash, and the connection secret).

use crate::core::wire;

use super::fact::ConnectionResponseFact;

pub const TYPE_CONNECTION_RESPONSE: u8 = 44;
pub const FACT_BYTES: usize = 1 + 32 * 9;

pub fn encode_fact(fact: &ConnectionResponseFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_CONNECTION_RESPONSE, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.from_endpoint);
    out[33..65].copy_from_slice(&fact.to_endpoint);
    out[65..97].copy_from_slice(&fact.request_id);
    out[97..129].copy_from_slice(&fact.invite_secret_event_id);
    out[129..161].copy_from_slice(&fact.initiator_ephemeral_secret_event_id);
    out[161..193].copy_from_slice(&fact.responder_ephemeral_secret_event_id);
    out[193..225].copy_from_slice(&fact.responder_ephemeral_public_key);
    out[225..257].copy_from_slice(&fact.handshake_hash);
    out[257..289].copy_from_slice(&fact.connection_secret);
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionResponseFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_CONNECTION_RESPONSE {
        return Err("expected connection response fact".to_string());
    }
    let mut from_endpoint = [0; 32];
    from_endpoint.copy_from_slice(&bytes[1..33]);
    let mut to_endpoint = [0; 32];
    to_endpoint.copy_from_slice(&bytes[33..65]);
    let mut request_id = [0; 32];
    request_id.copy_from_slice(&bytes[65..97]);
    let mut invite_secret_event_id = [0; 32];
    invite_secret_event_id.copy_from_slice(&bytes[97..129]);
    let mut initiator_ephemeral_secret_event_id = [0; 32];
    initiator_ephemeral_secret_event_id.copy_from_slice(&bytes[129..161]);
    let mut responder_ephemeral_secret_event_id = [0; 32];
    responder_ephemeral_secret_event_id.copy_from_slice(&bytes[161..193]);
    let mut responder_ephemeral_public_key = [0; 32];
    responder_ephemeral_public_key.copy_from_slice(&bytes[193..225]);
    let mut handshake_hash = [0; 32];
    handshake_hash.copy_from_slice(&bytes[225..257]);
    let mut connection_secret = [0; 32];
    connection_secret.copy_from_slice(&bytes[257..289]);
    Ok(ConnectionResponseFact {
        from_endpoint,
        to_endpoint,
        request_id,
        invite_secret_event_id,
        initiator_ephemeral_secret_event_id,
        responder_ephemeral_secret_event_id,
        responder_ephemeral_public_key,
        handshake_hash,
        connection_secret,
    })
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
            invite_secret_event_id: [4; 32],
            initiator_ephemeral_secret_event_id: [5; 32],
            responder_ephemeral_secret_event_id: [6; 32],
            responder_ephemeral_public_key: [7; 32],
            handshake_hash: [8; 32],
            connection_secret: [9; 32],
        }
    }

    #[test]
    fn connection_response_roundtrips_fixed_width() {
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
