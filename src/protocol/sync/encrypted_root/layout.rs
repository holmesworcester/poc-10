//! Fixed-width layout for sync encrypted-root advertisements.
//!
//! Encrypted-root facts are small sync control records, so their layout is only
//! a type tag plus the ids needed to find the encrypted payload dependency and
//! key wrap. Keep this file byte-focused; auth modules validate the
//! payloads named by these ids.

use crate::core::wire;

use super::fact::EncryptedRootFact;

pub const TYPE_ENCRYPTED_ROOT: u8 = 161;
pub const ENCODED_BYTES: usize = 1 + 32 + 32 + 32 + 32;

pub fn encode_fact(fact: &EncryptedRootFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; ENCODED_BYTES];
    wire::put_u8(TYPE_ENCRYPTED_ROOT, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.fact_id);
    out[65..97].copy_from_slice(&fact.dependency_id);
    out[97..129].copy_from_slice(&fact.key_wrap_id);
    Ok(out)
}

pub fn decode_fact(bytes: &[u8]) -> Result<EncryptedRootFact, String> {
    wire::expect_len(bytes, ENCODED_BYTES).map_err(wire_err)?;
    let tag = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if tag != TYPE_ENCRYPTED_ROOT {
        return Err("expected encrypted root".to_string());
    }
    Ok(EncryptedRootFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        fact_id: bytes[33..65].try_into().unwrap(),
        dependency_id: bytes[65..97].try_into().unwrap(),
        key_wrap_id: bytes[97..129].try_into().unwrap(),
    })
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
