//! Canonical byte encoding for content-file-slice facts with one padded BAO
//! proof slot.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths. It does not sign, authenticate, inspect context, or materialize rows.
//!
//! Body shape:
//!   tag (u8)
//!   workspace_id (32)
//!   created_at_ms (u64be)
//!   file_id (32)
//!   slice_index (u32be)
//!   proof (FixedSlot<FILE_SLICE_BAO_PROOF_BYTES>)

use crate::core::wire;
use crate::core::wire::FixedLayout;

use super::fact::{ContentFileSliceFact, FILE_SLICE_BAO_PROOF_BYTES};

pub const TYPE_CONTENT_FILE_SLICE: u8 = 55;
pub const FACT_PREFIX_BYTES: usize = 1 + 32 + 8 + 32 + 4 + 32 + 32;
pub const CONTENT_FILE_SLICE_BYTES: usize =
    FACT_PREFIX_BYTES + wire::FixedSlot::<FILE_SLICE_BAO_PROOF_BYTES>::LEN;
pub fn encode_fact(fact: &ContentFileSliceFact) -> Result<Vec<u8>, String> {
    let mut out = wire::Writer::with_capacity(CONTENT_FILE_SLICE_BYTES);
    out.u8(TYPE_CONTENT_FILE_SLICE);
    out.fixed(&fact.workspace_id);
    out.u64be(fact.created_at_ms);
    out.fixed(&fact.file_id);
    out.u32be(fact.slice_index);
    out.fixed(&fact.signer_id);
    out.fixed(&fact.signer_public_key);
    out.fixed_slot_value(&fact.proof).map_err(wire_err)?;
    out.finish_exact(CONTENT_FILE_SLICE_BYTES).map_err(wire_err)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
