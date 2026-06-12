//! Bundled connection-frame fact construction helpers.

use crate::core::crypto::{self, XChaCha20Poly1305Nonce};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::wire::{FixedBytes, FixedSlot};

use super::encode;
use super::fact::ConnectionFrameBundleFact;

const INNER_BUNDLE_TAG: &[u8; 4] = b"TIB1";
const INNER_BUNDLE_VERSION: u8 = 1;

pub fn fact_from_wire(frame: &[u8], local_timestamp_ms: u64) -> Result<Fact, String> {
    let fact = ConnectionFrameBundleFact {
        frame: exact_frame_slot(frame)?,
    };
    Ok(Fact::new(
        FactScope::Local,
        local_timestamp_ms,
        encode::encode_fact(&fact)?,
    ))
}

pub fn connection_send_nonce(
    connection_id: FactId,
    sender_endpoint_id: FactId,
    receiver_endpoint_id: FactId,
    fact_ids: &[FactId],
) -> XChaCha20Poly1305Nonce {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:connection::frame-connection-send-nonce:v1:");
    hash.update(&connection_id);
    hash.update(&sender_endpoint_id);
    hash.update(&receiver_endpoint_id);
    hash.update(&(fact_ids.len() as u32).to_be_bytes());
    for fact_id in fact_ids {
        hash.update(fact_id);
    }
    let digest = hash.finalize();
    let mut nonce = [0; 24];
    nonce.copy_from_slice(&digest.as_bytes()[..24]);
    nonce
}

pub fn seal_connection_send_frame(
    connection_id: FactId,
    sender_endpoint_id: FactId,
    receiver_endpoint_id: FactId,
    connection_secret: crypto::XChaCha20Poly1305Key,
    fact_ids: &[FactId],
    facts: &[Vec<u8>],
) -> Result<Vec<u8>, String> {
    seal_connection_frame(
        connection_id,
        sender_endpoint_id,
        receiver_endpoint_id,
        connection_secret,
        connection_send_nonce(
            connection_id,
            sender_endpoint_id,
            receiver_endpoint_id,
            fact_ids,
        ),
        facts,
    )
}

pub fn seal_connection_frame(
    connection_id: FactId,
    sender_endpoint_id: FactId,
    receiver_endpoint_id: FactId,
    connection_secret: crypto::XChaCha20Poly1305Key,
    nonce: XChaCha20Poly1305Nonce,
    facts: &[Vec<u8>],
) -> Result<Vec<u8>, String> {
    let plaintext =
        encode_fixed_slot_inner_bundle(facts, sender_endpoint_id, receiver_endpoint_id)?;
    let aad = encode::frame_associated_data(connection_id, nonce);
    let ciphertext =
        crypto::xchacha20poly1305_encrypt(&connection_secret, &aad, &nonce, &plaintext)?;
    encode::encode_frame_bytes(FixedBytes(connection_id), FixedBytes(nonce), &ciphertext)
        .map_err(encode::wire_err)
}

fn exact_frame_slot<const N: usize>(frame: &[u8]) -> Result<FixedSlot<N>, String> {
    if frame.len() != N {
        return Err(format!("connection frame must be exactly {N} bytes"));
    }
    FixedSlot::new(frame).map_err(|err| format!("connection frame bytes: {err}"))
}

fn encode_fixed_slot_inner_bundle(
    facts: &[Vec<u8>],
    sender_endpoint_id: FactId,
    receiver_endpoint_id: FactId,
) -> Result<Vec<u8>, String> {
    if facts.is_empty() {
        return Err("connection::frame inner bundle must contain at least one fact".to_string());
    }
    if facts.len() > encode::CONNECTION_FRAME_BUNDLE_FACT_SLOTS {
        return Err(format!(
            "connection::frame bundle has {} facts, max {}",
            facts.len(),
            encode::CONNECTION_FRAME_BUNDLE_FACT_SLOTS
        ));
    }
    let mut out = vec![0; encode::CONNECTION_FRAME_BUNDLE_PLAINTEXT_BYTES];
    let mut offset = 0;
    put(&mut out, &mut offset, INNER_BUNDLE_TAG)?;
    put(&mut out, &mut offset, &[INNER_BUNDLE_VERSION])?;
    put(&mut out, &mut offset, &sender_endpoint_id)?;
    put(&mut out, &mut offset, &receiver_endpoint_id)?;
    put_u32(&mut out, &mut offset, facts.len())?;
    for fact in facts {
        if fact.len() > encode::CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES {
            return Err(format!(
                "connection::frame bundle fact has {} bytes, max {}",
                fact.len(),
                encode::CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES
            ));
        }
        put_u32(&mut out, &mut offset, fact.len())?;
        put(&mut out, &mut offset, fact)?;
        offset += encode::CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES - fact.len();
    }
    Ok(out)
}

fn put_u32(out: &mut [u8], offset: &mut usize, value: usize) -> Result<(), String> {
    let value = u32::try_from(value)
        .map_err(|_| format!("connection::frame inner length too large: {value}"))?;
    put(out, offset, &value.to_be_bytes())
}

fn put(out: &mut [u8], offset: &mut usize, bytes: &[u8]) -> Result<(), String> {
    let end = offset
        .checked_add(bytes.len())
        .ok_or_else(|| "connection::frame inner bundle length overflow".to_string())?;
    if end > out.len() {
        return Err("connection::frame inner bundle exceeds fixed slot".to_string());
    }
    out[*offset..end].copy_from_slice(bytes);
    *offset = end;
    Ok(())
}
