//! Canonical byte encoding for content-file facts with a padded sealed-metadata
//! slot.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths. It does not sign, authenticate, inspect context, or materialize rows.
//!
//! Body shape:
//!   tag (u8)
//!   workspace_id (32)
//!   created_at_ms (u64be)
//!   message_id (32)
//!   author_user_id (32)
//!   file_id (32)
//!   blob_bytes (u64be)
//!   total_slices (u32be)
//!   slice_bytes (u32be)
//!   root_hash (32)
//!   sealed_metadata (FixedSlot<SEALED_METADATA_BYTES>)

use crate::core::crypto::ED25519_SIGNATURE_BYTES;
use crate::core::wire;
use crate::core::wire::FixedLayout;

use super::fact::{ContentFileFact, FILE_ROOT_HASH_BYTES, SEALED_METADATA_BYTES};

pub const TYPE_CONTENT_FILE: u8 = 54;
pub const FACT_PREFIX_BYTES: usize =
    1 + 32 + 8 + 32 + 32 + 32 + 32 + 32 + 8 + 4 + 4 + FILE_ROOT_HASH_BYTES;
pub const CONTENT_FILE_BYTES: usize =
    FACT_PREFIX_BYTES + wire::FixedSlot::<SEALED_METADATA_BYTES>::LEN + ED25519_SIGNATURE_BYTES;
pub fn encode_fact(fact: &ContentFileFact) -> Result<Vec<u8>, String> {
    let mut out = wire::Writer::with_capacity(CONTENT_FILE_BYTES);
    out.u8(TYPE_CONTENT_FILE);
    out.fixed(&fact.workspace_id);
    out.u64be(fact.created_at_ms);
    out.fixed(&fact.message_id);
    out.fixed(&fact.author_user_id);
    out.fixed(&fact.signer_id);
    out.fixed(&fact.signer_public_key);
    out.fixed(&fact.file_id);
    out.u64be(fact.blob_bytes);
    out.u32be(fact.total_slices);
    out.u32be(fact.slice_bytes);
    out.fixed(&fact.root_hash);
    out.fixed_slot_value(&fact.sealed_metadata)
        .map_err(wire_err)?;
    out.fixed(&fact.signature);
    out.finish_exact(CONTENT_FILE_BYTES).map_err(wire_err)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
