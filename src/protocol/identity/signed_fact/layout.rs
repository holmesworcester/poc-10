//! Fixed-slot layout for shared signed-fact envelopes.
//!
//! The signed envelope gives many fact families one canonical signature format:
//! signer id, signer public key, inner type, padded payload slot, and Ed25519
//! signature. Encoding rejects nested signed facts and private local payload
//! types so signatures cannot accidentally publish local secret material.
//!
//! Keep byte-level envelope rules here. Projectors that consume signed facts
//! must still verify workspace membership and role-specific authority.

use crate::core::crypto::{self, ED25519_SIGNATURE_BYTES};
use crate::core::wire;
use crate::core::wire::{FixedLayout, FixedSlot};

use super::fact::{LocalSignerSecretFact, SignedFactEnvelope, SIGNED_FACT_PAYLOAD_BYTES};

pub const TYPE_SIGNED_FACT: u8 = 132;
pub const TYPE_LOCAL_SIGNER_SECRET: u8 = 133;
const TYPE_LOCAL_KEY_SECRET: u8 = 152;
const TYPE_LOCAL_HISTORY_NODE_SECRET: u8 = 153;
const TYPE_LOCAL_RECIPIENT_KEY: u8 = 156;
pub const SIGNED_FACT_BYTES: usize =
    1 + 32 + 32 + 1 + FixedSlot::<SIGNED_FACT_PAYLOAD_BYTES>::LEN + ED25519_SIGNATURE_BYTES;
pub const LOCAL_SIGNER_SECRET_BYTES: usize = 1 + 32 + 32 + 32 + 32;

pub fn encode_local_signer_secret(fact: &LocalSignerSecretFact) -> Result<Vec<u8>, String> {
    validate_local_signer_secret(fact)?;
    let mut out = vec![0; LOCAL_SIGNER_SECRET_BYTES];
    wire::put_u8(TYPE_LOCAL_SIGNER_SECRET, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&fact.workspace_id);
    out[33..65].copy_from_slice(&fact.signer_id);
    out[65..97].copy_from_slice(&fact.public_key);
    out[97..129].copy_from_slice(&fact.private_key);
    Ok(out)
}

pub fn decode_local_signer_secret(bytes: &[u8]) -> Result<LocalSignerSecretFact, String> {
    wire::expect_len(bytes, LOCAL_SIGNER_SECRET_BYTES).map_err(wire_err)?;
    expect_tag(bytes, TYPE_LOCAL_SIGNER_SECRET, "local signer secret")?;
    let fact = LocalSignerSecretFact {
        workspace_id: bytes[1..33].try_into().unwrap(),
        signer_id: bytes[33..65].try_into().unwrap(),
        public_key: bytes[65..97].try_into().unwrap(),
        private_key: bytes[97..129].try_into().unwrap(),
    };
    validate_local_signer_secret(&fact)?;
    Ok(fact)
}

pub fn encode_signed_fact(envelope: &SignedFactEnvelope) -> Result<Vec<u8>, String> {
    validate_payload(envelope.inner_type, &envelope.payload)?;
    if envelope.signer_id.iter().all(|byte| *byte == 0) {
        return Err("signed fact signer_id cannot be empty".to_string());
    }
    if envelope.signer_public_key.iter().all(|byte| *byte == 0) {
        return Err("signed fact signer_public_key cannot be empty".to_string());
    }
    let payload =
        FixedSlot::<SIGNED_FACT_PAYLOAD_BYTES>::new(&envelope.payload).map_err(wire_err)?;
    let mut out = vec![0; SIGNED_FACT_BYTES];
    write_signing_fields(
        envelope,
        &payload,
        &mut out[..SIGNED_FACT_BYTES - ED25519_SIGNATURE_BYTES],
    )?;
    out[SIGNED_FACT_BYTES - ED25519_SIGNATURE_BYTES..].copy_from_slice(&envelope.signature);
    Ok(out)
}

pub fn decode_signed_fact(bytes: &[u8]) -> Result<SignedFactEnvelope, String> {
    wire::expect_len(bytes, SIGNED_FACT_BYTES).map_err(wire_err)?;
    expect_tag(bytes, TYPE_SIGNED_FACT, "signed fact")?;
    let payload = FixedSlot::<SIGNED_FACT_PAYLOAD_BYTES>::decode(
        &bytes[66..66 + FixedSlot::<SIGNED_FACT_PAYLOAD_BYTES>::LEN],
    )
    .map_err(wire_err)?;
    let envelope = SignedFactEnvelope {
        signer_id: bytes[1..33].try_into().unwrap(),
        signer_public_key: bytes[33..65].try_into().unwrap(),
        inner_type: bytes[65],
        payload: payload.bytes().to_vec(),
        signature: bytes[SIGNED_FACT_BYTES - ED25519_SIGNATURE_BYTES..SIGNED_FACT_BYTES]
            .try_into()
            .unwrap(),
    };
    validate_payload(envelope.inner_type, &envelope.payload)?;
    Ok(envelope)
}

pub fn verify_signed_fact(envelope: &SignedFactEnvelope) -> Result<(), String> {
    if crypto::ed25519_verify(
        &envelope.signer_public_key,
        &signing_bytes(envelope)?,
        &envelope.signature,
    ) {
        Ok(())
    } else {
        Err("signed fact signature verification failed".to_string())
    }
}

pub fn signing_bytes(envelope: &SignedFactEnvelope) -> Result<Vec<u8>, String> {
    validate_payload(envelope.inner_type, &envelope.payload)?;
    let payload =
        FixedSlot::<SIGNED_FACT_PAYLOAD_BYTES>::new(&envelope.payload).map_err(wire_err)?;
    let mut out = vec![0; SIGNED_FACT_BYTES - ED25519_SIGNATURE_BYTES];
    write_signing_fields(envelope, &payload, &mut out)?;
    Ok(out)
}

fn write_signing_fields(
    envelope: &SignedFactEnvelope,
    payload: &FixedSlot<SIGNED_FACT_PAYLOAD_BYTES>,
    out: &mut [u8],
) -> Result<(), String> {
    wire::expect_len(out, SIGNED_FACT_BYTES - ED25519_SIGNATURE_BYTES).map_err(wire_err)?;
    wire::put_u8(TYPE_SIGNED_FACT, &mut out[0..1]).map_err(wire_err)?;
    out[1..33].copy_from_slice(&envelope.signer_id);
    out[33..65].copy_from_slice(&envelope.signer_public_key);
    wire::put_u8(envelope.inner_type, &mut out[65..66]).map_err(wire_err)?;
    payload.encode(&mut out[66..]).map_err(wire_err)?;
    Ok(())
}

fn validate_payload(inner_type: u8, payload: &[u8]) -> Result<(), String> {
    let Some(actual_type) = payload.first().copied() else {
        return Err("signed fact payload is empty".to_string());
    };
    if actual_type != inner_type {
        return Err("signed fact inner type does not match payload".to_string());
    }
    if actual_type == TYPE_SIGNED_FACT {
        return Err("nested signed facts are not allowed".to_string());
    }
    if private_payload_type(actual_type) {
        return Err("private local facts cannot be signed".to_string());
    }
    Ok(())
}

fn validate_local_signer_secret(fact: &LocalSignerSecretFact) -> Result<(), String> {
    if fact.workspace_id.iter().all(|byte| *byte == 0) {
        return Err("local signer secret workspace_id cannot be empty".to_string());
    }
    if fact.signer_id.iter().all(|byte| *byte == 0) {
        return Err("local signer secret signer_id cannot be empty".to_string());
    }
    if fact.private_key.iter().all(|byte| *byte == 0) {
        return Err("local signer secret private_key cannot be empty".to_string());
    }
    if crypto::ed25519_public_key(&fact.private_key) != fact.public_key {
        return Err("local signer secret public_key does not match private_key".to_string());
    }
    Ok(())
}

fn private_payload_type(actual_type: u8) -> bool {
    matches!(
        actual_type,
        TYPE_LOCAL_SIGNER_SECRET
            | TYPE_LOCAL_KEY_SECRET
            | TYPE_LOCAL_HISTORY_NODE_SECRET
            | TYPE_LOCAL_RECIPIENT_KEY
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
