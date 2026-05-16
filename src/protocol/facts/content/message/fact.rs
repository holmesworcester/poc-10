//! Content-message fact shape for the poc-10 target tree.
//!
//! A content message is the public-shape author/timestamp/leaf metadata for a
//! chat post. The actual ciphertext lives in the sibling `content::sealed_message`
//! module; this fact carries an opaque `sealed_body_ref` (the fact id of the
//! sealed payload) plus the canonical fields the projector needs to materialize
//! a row keyed by `(workspace_id, message_id)`.
//!
//! Legacy parity gaps (intentional, deferred to later slices):
//!  - Legacy validates a signed envelope around the payload; the target
//!    `identity::signed_fact` envelope is a separate fact module.
//!  - Legacy resolves a disappearing-messages policy and stamps
//!    `expires_at_minute`; that policy module is not ported.
//!  - Legacy binds the leaf coordinate via a per-message leaf event dependency;
//!    here we only carry the `leaf_id` and `minute` hints.
//!  - Legacy rejects expired-at-receive messages at admission with a tombstone
//!    write; the admit-check helper is omitted from this slice.

use crate::core::facts::FactId;

pub const UNIX_MINUTE_MS: u64 = 60_000;

pub type WorkspaceId = FactId;
pub type AuthorId = FactId;
pub type FrontierId = FactId;

/// Public-shape content-message fact. Plaintext text never appears on the
/// wire — the projector only emits row metadata and the opaque
/// `sealed_body_ref` pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentMessageFact {
    pub workspace_id: WorkspaceId,
    pub author_user_id: AuthorId,
    pub created_at_ms: u64,
    pub frontier_id: FrontierId,
    pub minute: u64,
    pub leaf_id: FactId,
    pub sealed_body_ref: FactId,
}

/// Convenience: derive the authoring `unix_minute` from `created_at_ms`. The
/// fact carries `minute` explicitly so peers do not have to recompute, but
/// admission helpers may want to compare.
pub fn unix_minute_for(created_at_ms: u64) -> u64 {
    created_at_ms / UNIX_MINUTE_MS
}
