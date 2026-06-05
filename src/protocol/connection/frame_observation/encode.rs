//! Canonical byte encoding for received connection-frame observation facts.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths, and the canonical origin-addr normalization applied while encoding.

use crate::core::wire::{self, FixedLayout, FixedSlot};
use crate::protocol::connection::fact_receipt::author::normalize_origin_addr_bytes;
use crate::protocol::connection::fact_receipt::fact::{OriginAddr, ORIGIN_ADDR_BYTES};

use super::fact::ConnectionFrameObservationFact;

pub const TYPE_CONNECTION_FRAME_OBSERVATION: u8 = 173;
pub const CONNECTION_FRAME_OBSERVATION_FACT_BYTES: usize =
    1 + 32 + FixedSlot::<ORIGIN_ADDR_BYTES>::LEN + wire::U64_BYTES;

pub(crate) const FRAME_FACT_OFFSET: usize = 1;
pub(crate) const ORIGIN_OFFSET: usize = FRAME_FACT_OFFSET + 32;
pub(crate) const RECEIVED_AT_OFFSET: usize = ORIGIN_OFFSET + FixedSlot::<ORIGIN_ADDR_BYTES>::LEN;

pub fn encode_fact(fact: &ConnectionFrameObservationFact) -> Result<Vec<u8>, String> {
    let origin_addr = normalize_origin_addr_bytes(fact.origin_addr.bytes())?;
    let origin_addr = OriginAddr::new(&origin_addr).map_err(wire_err)?;
    let mut out = vec![0; CONNECTION_FRAME_OBSERVATION_FACT_BYTES];
    wire::put_u8(TYPE_CONNECTION_FRAME_OBSERVATION, &mut out[0..1]).map_err(wire_err)?;
    out[FRAME_FACT_OFFSET..ORIGIN_OFFSET].copy_from_slice(&fact.frame_fact_id);
    origin_addr
        .encode(&mut out[ORIGIN_OFFSET..RECEIVED_AT_OFFSET])
        .map_err(wire_err)?;
    wire::put_u64be(
        fact.received_at_local_ms,
        &mut out[RECEIVED_AT_OFFSET..CONNECTION_FRAME_OBSERVATION_FACT_BYTES],
    )
    .map_err(wire_err)?;
    Ok(out)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
