//! Shared signed-fact envelope types for protocol modules.
//!
//! Signed envelopes wrap one non-local payload with signer identity, public
//! key, and signature. The envelope is a transport and authority primitive:
//! layout fixes the bytes, create signs them, and content or identity
//! projectors decide whether the signer has the right role for the inner fact.
//! Local signer secrets live here too because they are the private counterpart
//! used to create envelopes on this node.

use crate::core::crypto::{Ed25519PrivateKey, Ed25519PublicKey, Ed25519Signature};
use crate::core::facts::FactId;

pub type SignerId = FactId;

pub const SIGNED_FACT_PAYLOAD_BYTES: usize = 512;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSignerSecretFact {
    pub workspace_id: FactId,
    pub signer_id: SignerId,
    pub public_key: Ed25519PublicKey,
    pub private_key: Ed25519PrivateKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedFactEnvelope {
    pub signer_id: SignerId,
    pub signer_public_key: Ed25519PublicKey,
    pub inner_type: u8,
    pub payload: Vec<u8>,
    pub signature: Ed25519Signature,
}
