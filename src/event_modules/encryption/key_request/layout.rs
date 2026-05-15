//! Fixed-width layout for key-request facts.

use super::fact::KeyRequestFact;
use crate::core::wire;

pub const TYPE_KEY_REQUEST: u8 = 154;
pub const KEY_REQUEST_BYTES: usize = 1 + 32 + 32 + 32 + 32 + 32 + 8;

pub fn encode_key_request(fact: &KeyRequestFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; KEY_REQUEST_BYTES];
    wire::put_u8(TYPE_KEY_REQUEST, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.requester_endpoint_id);
    out[65..97].copy_from_slice(&fact.responder_endpoint_id);
    out[97..129].copy_from_slice(&fact.frontier_id);
    out[129..161].copy_from_slice(&fact.recipient_key_id);
    wire::put_u64be(fact.created_at_ms, &mut out[161..169]).map_err(wire_err)?;
    Ok(out)
}

pub fn decode_key_request(bytes: &[u8]) -> Result<KeyRequestFact, String> {
    wire::expect_len(bytes, KEY_REQUEST_BYTES).map_err(wire_err)?;
    expect_tag(bytes, TYPE_KEY_REQUEST, "key request")?;
    Ok(KeyRequestFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        requester_endpoint_id: bytes[33..65].try_into().unwrap(),
        responder_endpoint_id: bytes[65..97].try_into().unwrap(),
        frontier_id: bytes[97..129].try_into().unwrap(),
        recipient_key_id: bytes[129..161].try_into().unwrap(),
        created_at_ms: wire::take_u64be(&bytes[161..169]).map_err(wire_err)?,
    })
}

fn expect_tag(bytes: &[u8], expected: u8, label: &str) -> Result<(), String> {
    let actual = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!("expected {label}"))
    }
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
