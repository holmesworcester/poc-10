//! Fixed-width layout for sync key-wrap availability facts.
//!
//! Key-wrap availability is an id-only sync signal. The layout guarantees a
//! canonical workspace id and key-wrap id pair, while projection and auth
//! handlers decide whether the signed wrap itself is valid and useful.

use crate::core::wire;

use super::fact::KeyWrapAvailableFact;

pub const TYPE_KEY_WRAP_AVAILABLE: u8 = 163;
pub const ENCODED_BYTES: usize = 1 + 32 + 32;

pub fn encode_fact(fact: &KeyWrapAvailableFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; ENCODED_BYTES];
    wire::put_u8(TYPE_KEY_WRAP_AVAILABLE, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.key_wrap_id);
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<KeyWrapAvailableFact, String> {
    wire::expect_len(bytes, ENCODED_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_KEY_WRAP_AVAILABLE {
        return Err("expected sync key wrap available".to_string());
    }
    Ok(KeyWrapAvailableFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        key_wrap_id: bytes[33..65].try_into().unwrap(),
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
