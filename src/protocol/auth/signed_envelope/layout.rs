//! Fixed-slot layout for shared signed-envelope envelopes.
//!
//! The signed envelope gives many fact families one canonical signature format:
//! signer id, signer public key, inner type, padded payload slot, and Ed25519
//! signature. Encoding rejects nested signed envelopes and private local payload
//! types so signatures cannot accidentally publish local secret material.
//!
//! Keep byte-level envelope rules here. Projectors that consume signed envelopes
//! must still verify workspace membership and role-specific authority.

use crate::core::crypto::{self, ED25519_SIGNATURE_BYTES};
use crate::core::wire;
use crate::core::wire::{FixedLayout, FixedSlot};

use super::fact::{SignedEnvelope, SignedEnvelopePayload, SIGNED_ENVELOPE_PAYLOAD_BYTES};

pub const TYPE_SIGNED_ENVELOPE: u8 = 132;
const TYPE_LOCAL_KEY_SECRET: u8 = 152;
const TYPE_LOCAL_HISTORY_NODE_SECRET: u8 = 153;
const TYPE_LOCAL_RECIPIENT_KEY: u8 = 156;
const TYPE_LOCAL_SECRET_RETIREMENT: u8 = 157;
pub const SIGNED_ENVELOPE_BYTES: usize =
    1 + 32 + 32 + 1 + FixedSlot::<SIGNED_ENVELOPE_PAYLOAD_BYTES>::LEN + ED25519_SIGNATURE_BYTES;

pub fn encode_signed_envelope(envelope: &SignedEnvelope) -> Result<Vec<u8>, String> {
    validate_payload(envelope.inner_type, &envelope.payload)?;
    if envelope.signer_id.iter().all(|byte| *byte == 0) {
        return Err("signed envelope signer_id cannot be empty".to_string());
    }
    if envelope.signer_public_key.iter().all(|byte| *byte == 0) {
        return Err("signed envelope signer_public_key cannot be empty".to_string());
    }
    let mut out = vec![0; SIGNED_ENVELOPE_BYTES];
    write_signing_fields(
        envelope,
        &envelope.payload,
        &mut out[..SIGNED_ENVELOPE_BYTES - ED25519_SIGNATURE_BYTES],
    )?;
    out[SIGNED_ENVELOPE_BYTES - ED25519_SIGNATURE_BYTES..].copy_from_slice(&envelope.signature);
    Ok(out)
}

pub fn decode_signed_envelope(bytes: &[u8]) -> Result<SignedEnvelope, String> {
    wire::expect_len(bytes, SIGNED_ENVELOPE_BYTES).map_err(wire_err)?;
    expect_tag(bytes, TYPE_SIGNED_ENVELOPE, "signed envelope")?;
    let payload = FixedSlot::<SIGNED_ENVELOPE_PAYLOAD_BYTES>::decode(
        &bytes[66..66 + FixedSlot::<SIGNED_ENVELOPE_PAYLOAD_BYTES>::LEN],
    )
    .map_err(wire_err)?;
    let envelope = SignedEnvelope {
        signer_id: bytes[1..33].try_into().unwrap(),
        signer_public_key: bytes[33..65].try_into().unwrap(),
        inner_type: bytes[65],
        payload,
        signature: bytes[SIGNED_ENVELOPE_BYTES - ED25519_SIGNATURE_BYTES..SIGNED_ENVELOPE_BYTES]
            .try_into()
            .unwrap(),
    };
    validate_payload(envelope.inner_type, &envelope.payload)?;
    Ok(envelope)
}

pub fn verify_signed_envelope(envelope: &SignedEnvelope) -> Result<(), String> {
    if crypto::ed25519_verify(
        &envelope.signer_public_key,
        &signing_bytes(envelope)?,
        &envelope.signature,
    ) {
        Ok(())
    } else {
        Err("signed envelope signature verification failed".to_string())
    }
}

pub fn signing_bytes(envelope: &SignedEnvelope) -> Result<Vec<u8>, String> {
    validate_payload(envelope.inner_type, &envelope.payload)?;
    let mut out = vec![0; SIGNED_ENVELOPE_BYTES - ED25519_SIGNATURE_BYTES];
    write_signing_fields(envelope, &envelope.payload, &mut out)?;
    Ok(out)
}

fn write_signing_fields(
    envelope: &SignedEnvelope,
    payload: &SignedEnvelopePayload,
    out: &mut [u8],
) -> Result<(), String> {
    wire::expect_len(out, SIGNED_ENVELOPE_BYTES - ED25519_SIGNATURE_BYTES).map_err(wire_err)?;
    wire::put_u8(TYPE_SIGNED_ENVELOPE, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&envelope.signer_id);
    out[33..65].copy_from_slice(&envelope.signer_public_key);
    wire::put_u8(envelope.inner_type, &mut out[65..66]).map_err(wire_err)?;
    payload.encode(&mut out[66..]).map_err(wire_err)?;
    Ok(())
}

fn validate_payload(inner_type: u8, payload: &[u8]) -> Result<(), String> {
    let Some(actual_type) = payload.first().copied() else {
        return Err("signed envelope payload is empty".to_string());
    };
    if actual_type != inner_type {
        return Err("signed envelope inner type does not match payload".to_string());
    }
    if actual_type == TYPE_SIGNED_ENVELOPE {
        return Err("nested signed envelopes are not allowed".to_string());
    }
    if private_payload_type(actual_type) {
        return Err("private local facts cannot be signed".to_string());
    }
    Ok(())
}

fn private_payload_type(actual_type: u8) -> bool {
    matches!(
        actual_type,
        super::super::local_signer_secret::layout::TYPE_LOCAL_SIGNER_SECRET
            | TYPE_LOCAL_KEY_SECRET
            | TYPE_LOCAL_HISTORY_NODE_SECRET
            | TYPE_LOCAL_RECIPIENT_KEY
            | TYPE_LOCAL_SECRET_RETIREMENT
    )
}

fn expect_tag(bytes: &[u8], expected: u8, label: &str) -> Result<(), String> {
    let actual = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if actual == expected {
        Ok(())
    } else {
        Err(format!("expected {label}"))
    }
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
