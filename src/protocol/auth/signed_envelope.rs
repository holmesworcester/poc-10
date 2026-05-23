//! Signed envelope codec.
//!
//! The signed envelope is how identity authority wraps many protocol payloads
//! without changing the inner fact layout. This module owns the envelope bytes,
//! signature verification helpers, and typed payload extraction. Local signer
//! secrets are their own fact family; signed envelopes are decoded and verified
//! by the projectors that own the wrapped payload.

pub mod create;
pub mod fact;
pub mod layout;

pub use create::*;
pub use fact::*;

pub const TYPE_SIGNED_ENVELOPE: u8 = layout::TYPE_SIGNED_ENVELOPE;
pub const SIGNED_ENVELOPE_BYTES: usize = layout::SIGNED_ENVELOPE_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedPayload<T> {
    pub envelope: fact::SignedEnvelope,
    pub payload: T,
}

pub fn decode_envelope(bytes: &[u8]) -> Result<fact::SignedEnvelope, String> {
    layout::decode_signed_envelope(bytes)
}

pub fn verify_envelope(envelope: &fact::SignedEnvelope) -> Result<(), String> {
    layout::verify_signed_envelope(envelope)
}

pub fn decode_signed_payload<T>(
    fact: &crate::core::facts::Fact,
    expected_type: u8,
    label: &str,
    decode: impl FnOnce(&[u8]) -> Result<T, String>,
) -> Result<SignedPayload<T>, String> {
    let envelope =
        decode_envelope(fact.body()).map_err(|_| format!("{label} fact must be signed"))?;
    if envelope.inner_type != expected_type {
        return Err(format!("signed envelope does not contain {label}"));
    }
    let payload = decode(&envelope.payload)?;
    Ok(SignedPayload { envelope, payload })
}
