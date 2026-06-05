//! Canonical byte encoding for content-message-deletion target facts.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths. It does not sign, authenticate, inspect context, or materialize rows.
//!
//! Body shape:
//!   tag (u8)
//!   workspace_id (32)
//!   created_at_ms (u64be)
//!   target_message_id (32)
//!   target_frontier_id (32)
//!   target_minute (u64be)
//!   author_user_id (32)

use crate::core::crypto::ED25519_SIGNATURE_BYTES;
use crate::core::wire;

use super::fact::ContentMessageDeletionFact;

pub const TYPE_CONTENT_MESSAGE_DELETION: u8 = 51;

pub const CONTENT_MESSAGE_DELETION_BYTES: usize =
    1 + 32 + 8 + 32 + 32 + 8 + 32 + 32 + 32 + ED25519_SIGNATURE_BYTES;
pub fn encode_fact(fact: &ContentMessageDeletionFact) -> Result<Vec<u8>, String> {
    let mut out = wire::Writer::with_capacity(CONTENT_MESSAGE_DELETION_BYTES);
    out.u8(TYPE_CONTENT_MESSAGE_DELETION);
    out.fixed(&fact.workspace_id);
    out.u64be(fact.created_at_ms);
    out.fixed(&fact.target_message_id);
    out.fixed(&fact.target_frontier_id);
    out.u64be(fact.target_minute);
    out.fixed(&fact.author_user_id);
    out.fixed(&fact.signer_id);
    out.fixed(&fact.signer_public_key);
    out.fixed(&fact.signature);
    out.finish_exact(CONTENT_MESSAGE_DELETION_BYTES)
        .map_err(wire_err)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
