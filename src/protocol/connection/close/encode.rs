//! Canonical byte encoding for connection-close facts.
//!
//! This file owns byte construction only: the fact tag and the fixed
//! field order and width. It does not validate context or schedule cleanup.
//!
//! The close layout is fixed width:
//! `tag(1) || connection_id(32) || closed_at_ms(8)`. Encoding preserves this
//! exact shape so the close fact has a deterministic id.
//!
//! Change this file for close wire compatibility only. Context validation and
//! cleanup fanout belong in `project.rs`.

use crate::core::wire;

use super::fact::ConnectionCloseFact;

pub const TYPE_CONNECTION_CLOSE: u8 = 45;
pub const FACT_BYTES: usize = 1 + 32 + 8;

pub fn encode_fact(fact: &ConnectionCloseFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; FACT_BYTES];
    wire::put_u8(TYPE_CONNECTION_CLOSE, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.connection_id);
    wire::put_u64be(fact.closed_at_ms, &mut out[33..41]).map_err(wire_err)?;
    Ok(out)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
