//! Canonical byte encoding for cascade dependency fixtures.
//!
//! This file owns byte construction only: one type byte, one timestamp, an
//! explicit dependency count, padded dependency slots, and a deterministic
//! payload. The cascade harness stores staged facts as raw bytes, so this
//! encoding keeps the fixture canonical.

use super::fact::{CascadeTestFact, MAX_DEPS, PAYLOAD_BYTES};

pub const TYPE_CASCADE_TEST_FACT: u8 = 2;
pub const ENCODED_BYTES: usize = 1 + 8 + 1 + (MAX_DEPS * 32) + PAYLOAD_BYTES;

pub fn encode_fact(fact: &CascadeTestFact) -> Result<Vec<u8>, String> {
    let mut out = vec![0; ENCODED_BYTES];
    out[0] = TYPE_CASCADE_TEST_FACT;
    out[1..9].copy_from_slice(&fact.timestamp.to_be_bytes());
    out[9] = fact.dependencies.len() as u8;
    let mut offset = 10;
    for dependency in fact.dependencies.padded_ids() {
        out[offset..offset + 32].copy_from_slice(dependency);
        offset += 32;
    }
    out[offset..offset + PAYLOAD_BYTES].copy_from_slice(&fact.payload);
    Ok(out)
}
