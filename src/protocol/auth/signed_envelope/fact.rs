//! Shared signed-envelope types for protocol modules.
//!
//! Signed envelopes wrap one non-local payload with signer identity, public
//! key, and signature. The envelope is a connection and authority primitive:
//! layout fixes the bytes, create signs them, and content or auth
//! projectors decide whether the signer has the right role for the inner fact.

use crate::core::crypto::{Ed25519PublicKey, Ed25519Signature};
use crate::core::facts::FactId;
use crate::core::wire::FixedSlot;

pub type SignerId = FactId;

/// Fixed payload budget for signed protocol facts.
///
/// This is sized to the largest current signable inner fact. If a future
/// signable fact grows, update this constant and the connection-frame bundle
/// sizing guardrail together.
pub const SIGNED_ENVELOPE_PAYLOAD_BYTES: usize = 701;
pub type SignedEnvelopePayload = FixedSlot<SIGNED_ENVELOPE_PAYLOAD_BYTES>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEnvelope {
    pub signer_id: SignerId,
    pub signer_public_key: Ed25519PublicKey,
    pub inner_type: u8,
    pub payload: SignedEnvelopePayload,
    pub signature: Ed25519Signature,
}
