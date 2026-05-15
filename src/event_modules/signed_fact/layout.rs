//! Fixed-slot layout for target shared signed-fact envelopes.

use crate::core::crypto::{self, ED25519_SIGNATURE_BYTES};
use crate::core::wire;
use crate::core::wire::{FixedLayout, FixedSlot};

use super::fact::{SignedFactEnvelope, SIGNED_FACT_PAYLOAD_BYTES};

pub const TYPE_SIGNED_FACT: u8 = 132;
pub const SIGNED_FACT_BYTES: usize =
    1 + 32 + 32 + 1 + FixedSlot::<SIGNED_FACT_PAYLOAD_BYTES>::LEN + ED25519_SIGNATURE_BYTES;

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
    expect_tag(bytes)?;
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
    if !crypto::ed25519_verify(
        &envelope.signer_public_key,
        &signing_bytes(&envelope)?,
        &envelope.signature,
    ) {
        return Err("signed fact signature verification failed".to_string());
    }
    Ok(envelope)
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
    Ok(())
}

fn expect_tag(bytes: &[u8]) -> Result<(), String> {
    let actual = wire::take_u8(&bytes[0..1]).map_err(wire_err)?;
    if actual == TYPE_SIGNED_FACT {
        Ok(())
    } else {
        Err("expected signed fact".to_string())
    }
}

fn wire_err(err: wire::WireError) -> String {
    format!("{err:?}")
}
