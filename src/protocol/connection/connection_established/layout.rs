use crate::core::wire;

use super::fact::ConnectionEstablishedFact;

pub const TYPE_CONNECTION_ESTABLISHED: u8 = 178;
pub const FACT_BYTES: usize = 1 + 32 * 9 + 8;

pub fn encode_fact(fact: &ConnectionEstablishedFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_CONNECTION_ESTABLISHED, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.connection_id);
    out[33..65].copy_from_slice(&fact.from_endpoint);
    out[65..97].copy_from_slice(&fact.to_endpoint);
    out[97..129].copy_from_slice(&fact.request_id);
    out[129..161].copy_from_slice(&fact.initiator_ephemeral_secret_fact_id);
    out[161..193].copy_from_slice(&fact.responder_ephemeral_secret_fact_id);
    out[193..225].copy_from_slice(&fact.responder_ephemeral_public_key);
    out[225..257].copy_from_slice(&fact.handshake_hash);
    out[257..289].copy_from_slice(&fact.connection_secret);
    wire::put_u64be(fact.established_at_ms, &mut out[289..297]).map_err(wire_err)?;
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionEstablishedFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
    if wire::take_u8(&bytes[0..1]).map_err(wire_err)? != TYPE_CONNECTION_ESTABLISHED {
        return Err("expected connection_established fact".to_string());
    }
    let mut connection_id = [0; 32];
    connection_id.copy_from_slice(&bytes[1..33]);
    let mut from_endpoint = [0; 32];
    from_endpoint.copy_from_slice(&bytes[33..65]);
    let mut to_endpoint = [0; 32];
    to_endpoint.copy_from_slice(&bytes[65..97]);
    let mut request_id = [0; 32];
    request_id.copy_from_slice(&bytes[97..129]);
    let mut initiator_ephemeral_secret_fact_id = [0; 32];
    initiator_ephemeral_secret_fact_id.copy_from_slice(&bytes[129..161]);
    let mut responder_ephemeral_secret_fact_id = [0; 32];
    responder_ephemeral_secret_fact_id.copy_from_slice(&bytes[161..193]);
    let mut responder_ephemeral_public_key = [0; 32];
    responder_ephemeral_public_key.copy_from_slice(&bytes[193..225]);
    let mut handshake_hash = [0; 32];
    handshake_hash.copy_from_slice(&bytes[225..257]);
    let mut connection_secret = [0; 32];
    connection_secret.copy_from_slice(&bytes[257..289]);
    let established_at_ms = wire::take_u64be(&bytes[289..297]).map_err(wire_err)?;
    Ok(ConnectionEstablishedFact {
        connection_id,
        from_endpoint,
        to_endpoint,
        request_id,
        initiator_ephemeral_secret_fact_id,
        responder_ephemeral_secret_fact_id,
        responder_ephemeral_public_key,
        handshake_hash,
        connection_secret,
        established_at_ms,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> ConnectionEstablishedFact {
        ConnectionEstablishedFact {
            connection_id: [1; 32],
            from_endpoint: [2; 32],
            to_endpoint: [3; 32],
            request_id: [4; 32],
            initiator_ephemeral_secret_fact_id: [5; 32],
            responder_ephemeral_secret_fact_id: [6; 32],
            responder_ephemeral_public_key: [7; 32],
            handshake_hash: [8; 32],
            connection_secret: [9; 32],
            established_at_ms: 10,
        }
    }

    #[test]
    fn connection_established_roundtrip_fixed_width() {
        let bytes = encode_fact(&fact()).expect("encode");
        assert_eq!(bytes.len(), FACT_BYTES);
        assert_eq!(decode_fact(&bytes).expect("decode"), fact());
    }
}
