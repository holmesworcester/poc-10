//! Recipient key event types.
//!
//! A recipient key is a shared workspace fact that publishes the public X25519
//! key for one endpoint membership. The matching private material remains in a
//! local recipient key event.
//!
//! `previous_recipient_key_id` lets a recipient publish a replacement keypair
//! when its local F is wiped (forward-secrecy rotation per
//! `RULES.md` § "Forward Secrecy Requires Recipient Key Rotation On
//! Wrap-Bound Deletion"). When non-zero, the new event acts as both:
//!
//! * the tombstone of the previous pubkey (projector exact-deletes the old
//!   row and the wrap rows targeting it), and
//! * the introduction of the fresh pubkey (workspace's active recipient set
//!   for this endpoint flips over to the new key).
//!
//! When zero, the event is a fresh key publication with no predecessor.

use crate::core::crypto::{Ed25519PublicKey, Ed25519Signature, X25519PublicKey};
use crate::protocol::event_modules::types::EventId;

/// Sentinel meaning "no previous recipient key" — fresh introduction with no
/// supersession effect. Encoded on the wire as 32 zero bytes.
pub const NO_PREVIOUS_RECIPIENT_KEY: EventId = [0; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientKeyEvent {
    pub workspace_id: EventId,
    pub created_at_ms: u64,
    pub endpoint_shared_id: EventId,
    pub recipient_key: X25519PublicKey,
    /// `NO_PREVIOUS_RECIPIENT_KEY` (zero) for a fresh keypair publication;
    /// otherwise the event id of the recipient_key event being superseded.
    /// Carrying the predecessor in the canonical bytes lets every peer's
    /// projector treat the event as "tombstone + introduction" in one step
    /// without a separate `recipient_key_tombstone` event.
    pub previous_recipient_key_id: EventId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRecipientKeyEnvelope {
    pub signer_endpoint_shared_id: EventId,
    pub signer_public_key: Ed25519PublicKey,
    pub payload: Vec<u8>,
    pub signature: Ed25519Signature,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecipientKeyRow {
    pub workspace_id: EventId,
    pub recipient_key_id: EventId,
    pub created_at_ms: u64,
    pub endpoint_shared_id: EventId,
    pub recipient_key: X25519PublicKey,
    /// Mirrors the canonical event field. `NO_PREVIOUS_RECIPIENT_KEY` when
    /// this row is a fresh publication; otherwise the event id of the
    /// retired predecessor pubkey.
    pub previous_recipient_key_id: EventId,
}
