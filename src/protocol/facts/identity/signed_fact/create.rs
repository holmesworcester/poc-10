//! Constructors for shared signed-fact envelopes.
//!
//! Several identity and content facts travel as signed envelopes so peers can
//! verify who authored a payload without each fact family reinventing envelope
//! bytes. This module builds those envelopes and signs exactly the canonical
//! bytes defined by `layout`. It should remain a pure constructor; deciding
//! whether a signer is authorized belongs to the consuming projector.

use crate::core::crypto::{self, Ed25519PrivateKey};

use super::fact::{SignedFactEnvelope, SignerId};
use super::layout;

pub fn sign_payload(
    signer_id: SignerId,
    private_key: &Ed25519PrivateKey,
    payload: Vec<u8>,
) -> Result<SignedFactEnvelope, String> {
    let inner_type = payload
        .first()
        .copied()
        .ok_or_else(|| "signed fact payload is empty".to_string())?;
    let signer_public_key = crypto::ed25519_public_key(private_key);
    let mut envelope = SignedFactEnvelope {
        signer_id,
        signer_public_key,
        inner_type,
        payload,
        signature: [0; crypto::ED25519_SIGNATURE_BYTES],
    };
    envelope.signature = crypto::ed25519_sign(private_key, &layout::signing_bytes(&envelope)?);
    Ok(envelope)
}

pub fn sign_payload_bytes(
    signer_id: SignerId,
    private_key: &Ed25519PrivateKey,
    payload: Vec<u8>,
) -> Result<Vec<u8>, String> {
    layout::encode_signed_fact(&sign_payload(signer_id, private_key, payload)?)
}
