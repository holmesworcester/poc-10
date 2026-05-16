//! Fixed-width layout for sync shared-event availability.

use crate::core::wire;

use super::fact::SharedEventFact;

pub const TYPE_SHARED_EVENT: u8 = 162;
pub const ENCODED_BYTES: usize = 1 + 32 + 32;

pub fn encode_fact(fact: &SharedEventFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; ENCODED_BYTES];
    wire::put_u8(TYPE_SHARED_EVENT, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.event_id);
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<SharedEventFact, String> {
    wire::expect_len(bytes, ENCODED_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_SHARED_EVENT {
        return Err("expected sync shared event".to_string());
    }
    Ok(SharedEventFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        event_id: bytes[33..65].try_into().unwrap(),
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
