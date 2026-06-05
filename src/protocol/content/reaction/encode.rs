//! Canonical byte encoding for content-reaction target facts.
//!
//! This file owns byte construction only: the fact tag, fixed field order and
//! widths. It does not sign, authenticate, inspect context, or materialize rows.
//!
//! Body shape:
//!   tag (u8)
//!   workspace_id (32)
//!   created_at_ms (u64be)
//!   target_message_id (32)
//!   author_user_id (32)
//!   nonce (24)
//!   ciphertext (FixedSlot<REACTION_CIPHERTEXT_BYTES>)

use crate::core::crypto::ED25519_SIGNATURE_BYTES;
use crate::core::wire;

use super::fact::{ContentReactionFact, REACTION_CIPHERTEXT_BYTES, REACTION_NONCE_BYTES};

pub const TYPE_CONTENT_REACTION: u8 = 52;

pub const CONTENT_REACTION_BYTES: usize = 1
    + 32
    + 8
    + 32
    + 32
    + 32
    + 32
    + REACTION_NONCE_BYTES
    + 4
    + REACTION_CIPHERTEXT_BYTES
    + ED25519_SIGNATURE_BYTES;
pub fn encode_fact(fact: &ContentReactionFact) -> Result<Vec<u8>, String> {
    let mut out = wire::Writer::with_capacity(CONTENT_REACTION_BYTES);
    out.u8(TYPE_CONTENT_REACTION);
    out.fixed(&fact.workspace_id);
    out.u64be(fact.created_at_ms);
    out.fixed(&fact.target_message_id);
    out.fixed(&fact.author_user_id);
    out.fixed(&fact.signer_id);
    out.fixed(&fact.signer_public_key);
    out.fixed(&fact.nonce);
    out.fixed_slot_value(&fact.ciphertext).map_err(wire_err)?;
    out.fixed(&fact.signature);
    out.finish_exact(CONTENT_REACTION_BYTES).map_err(wire_err)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
