//! Canonical byte encoding for content-file-deletion target facts.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths. It does not sign, authenticate, inspect context, or materialize rows.
//!
//! Body shape:
//!   tag (u8)
//!   workspace_id (32)
//!   created_at_ms (u64be)
//!   target_file_id (32)
//!   author_user_id (32)

use crate::core::wire;

use super::fact::ContentFileDeletionFact;

pub const TYPE_CONTENT_FILE_DELETION: u8 = 53;

pub const CONTENT_FILE_DELETION_BYTES: usize = 1 + 32 + 8 + 32 + 32 + 32 + 32;
pub fn encode_fact(fact: &ContentFileDeletionFact) -> Result<Vec<u8>, String> {
    let mut out = wire::Writer::with_capacity(CONTENT_FILE_DELETION_BYTES);
    out.u8(TYPE_CONTENT_FILE_DELETION);
    out.fixed(&fact.workspace_id);
    out.u64be(fact.created_at_ms);
    out.fixed(&fact.target_file_id);
    out.fixed(&fact.author_user_id);
    out.fixed(&fact.signer_id);
    out.fixed(&fact.signer_public_key);
    out.finish_exact(CONTENT_FILE_DELETION_BYTES)
        .map_err(wire_err)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
