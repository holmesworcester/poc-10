use crate::core::wire;

use super::fact::ConnectionResponseReceivedFact;

pub const TYPE_CONNECTION_RESPONSE_RECEIVED: u8 = 177;
pub const FACT_BYTES: usize = 1 + 32 + 32 + 32 + 8;

pub fn encode_fact(fact: &ConnectionResponseReceivedFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_CONNECTION_RESPONSE_RECEIVED, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.response_id);
    out[33..65].copy_from_slice(&fact.request_id);
    out[65..97].copy_from_slice(&fact.receive_id);
    wire::put_u64be(fact.received_at_local_ms, &mut out[97..105]).map_err(wire_err)?;
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionResponseReceivedFact, String> {
    wire::expect_len(bytes, FACT_BYTES).map_err(wire_err)?;
    if wire::take_u8(&bytes[0..1]).map_err(wire_err)? != TYPE_CONNECTION_RESPONSE_RECEIVED {
        return Err("expected connection_response_received fact".to_string());
    }
    let mut response_id = [0; 32];
    response_id.copy_from_slice(&bytes[1..33]);
    let mut request_id = [0; 32];
    request_id.copy_from_slice(&bytes[33..65]);
    let mut receive_id = [0; 32];
    receive_id.copy_from_slice(&bytes[65..97]);
    let received_at_local_ms = wire::take_u64be(&bytes[97..105]).map_err(wire_err)?;
    Ok(ConnectionResponseReceivedFact {
        response_id,
        request_id,
        receive_id,
        received_at_local_ms,
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact() -> ConnectionResponseReceivedFact {
        ConnectionResponseReceivedFact {
            response_id: [1; 32],
            request_id: [2; 32],
            receive_id: [3; 32],
            received_at_local_ms: 4,
        }
    }

    #[test]
    fn connection_response_received_roundtrip_fixed_width() {
        let bytes = encode_fact(&fact()).expect("encode");
        assert_eq!(bytes.len(), FACT_BYTES);
        assert_eq!(decode_fact(&bytes).expect("decode"), fact());
    }
}
