//! Content-reaction fact shape for the poc-10 target tree.
//!
//! A reaction is a workspace-scoped emoji attached to a target message. The
//! emoji is sealed in a fixed-width ciphertext slot; the canonical fact body
//! carries the public envelope (workspace, target, author, nonce, ciphertext).
//! Per-message auth key-material metadata (history-node secret, frontier) is not part
//! of this fact body; the reaction carries only the sealed payload envelope
//! that projectors can authorize and sync idempotently.

use crate::core::facts::FactId;
use crate::core::wire::FixedSlot;

pub const REACTION_CIPHERTEXT_BYTES: usize = 80; // 64 emoji bytes + 16 poly1305 tag
pub const REACTION_NONCE_BYTES: usize = 24;
pub type ReactionCiphertext = FixedSlot<REACTION_CIPHERTEXT_BYTES>;

pub type WorkspaceId = FactId;
pub type AuthorId = FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentReactionFact {
    pub workspace_id: WorkspaceId,
    pub created_at_ms: u64,
    pub target_message_id: FactId,
    pub author_user_id: AuthorId,
    pub nonce: [u8; REACTION_NONCE_BYTES],
    pub ciphertext: ReactionCiphertext,
}
