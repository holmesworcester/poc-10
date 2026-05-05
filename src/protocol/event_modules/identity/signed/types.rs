//! Types for signed shared envelopes.
//!
//! A signed envelope authenticates one canonical inner event payload. Authority
//! rules belong to the projected inner event families; this type only carries
//! the signer dependency, signer public key, payload bytes, and Ed25519
//! signature needed to verify the envelope bytes.

use crate::core::crypto::{Ed25519PublicKey, Ed25519Signature};
use crate::protocol::event_modules::types::EventId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEnvelope {
    pub signer_event_id: EventId,
    pub signer_public_key: Ed25519PublicKey,
    pub inner_type: u8,
    pub payload: Vec<u8>,
    pub signature: Ed25519Signature,
}
