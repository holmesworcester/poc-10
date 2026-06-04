//! Canonical byte encoding for content-message facts.
//!
//! This file owns fixed field order, field widths, the fact tag, and the pure
//! signing transcript. It does not sign, authenticate, inspect context,
//! encrypt, decrypt, or materialize rows.
//!
//! Body shape:
//!   tag (u8)
//!   workspace_id (32)
//!   created_at_ms (u64be)
//!   author_user_id (32)
//!   signer_id (32)
//!   frontier_id (32)
//!   local_history_node_secret_id (32)
//!   expires_at_minute (u64be)
//!   retention_policy_id (32)
//!   minute (u64be)
//!   nonce (24)
//!   ciphertext (fixed slot)

use crate::core::crypto::ED25519_SIGNATURE_BYTES;
use crate::core::wire;

use super::fact::{ContentMessageFact, CIPHERTEXT_BYTES, NONCE_BYTES};

pub const TYPE_CONTENT_MESSAGE: u8 = 50;

pub const CONTENT_MESSAGE_BYTES: usize = 1
    + 32
    + 8
    + 32
    + 32
    + 32
    + 32
    + 32
    + 8
    + 32
    + 8
    + NONCE_BYTES
    + 4
    + CIPHERTEXT_BYTES
    + ED25519_SIGNATURE_BYTES;
const SIGNATURE_OFFSET: usize = CONTENT_MESSAGE_BYTES - ED25519_SIGNATURE_BYTES;

pub fn encode_fact(fact: &ContentMessageFact) -> Result<Vec<u8>, String> {
    let mut out = wire::Writer::with_capacity(CONTENT_MESSAGE_BYTES);
    out.u8(TYPE_CONTENT_MESSAGE);
    out.fixed(&fact.workspace_id);
    out.u64be(fact.created_at_ms);
    out.fixed(&fact.author_user_id);
    out.fixed(&fact.signer_id);
    out.fixed(&fact.signer_public_key);
    out.fixed(&fact.frontier_id);
    out.fixed(&fact.local_history_node_secret_id);
    out.u64be(fact.expires_at_minute);
    out.fixed(&fact.retention_policy_id);
    out.u64be(fact.minute);
    out.fixed(&fact.nonce);
    out.fixed_slot_value(&fact.ciphertext).map_err(wire_err)?;
    out.fixed(&fact.signature);
    out.finish_exact(CONTENT_MESSAGE_BYTES).map_err(wire_err)
}

pub fn signing_bytes(fact: &ContentMessageFact) -> Result<Vec<u8>, String> {
    wire::canonical_with_zeroed_field(&encode_fact(fact)?, SIGNATURE_OFFSET..CONTENT_MESSAGE_BYTES)
        .map_err(wire_err)
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
