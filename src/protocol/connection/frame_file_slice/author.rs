//! File-slice connection-frame fact construction helpers.

use crate::core::crypto::{self, XChaCha20Poly1305Nonce};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::wire::{FixedBytes, FixedSlot};
use crate::protocol::content::file_slice;

use super::encode;
use super::fact::ConnectionFrameFileSliceFact;

const INNER_BUNDLE_TAG: &[u8; 4] = b"TIB1";
const INNER_BUNDLE_VERSION: u8 = 1;
pub(crate) const INNER_BUNDLE_HEADER_BYTES: usize = 4 + 1 + 32 + 32 + 4;
const INNER_FACT_LEN_BYTES: usize = 4;

pub fn fact_from_wire(frame: &[u8], local_timestamp_ms: u64) -> Result<Fact, String> {
    let fact = ConnectionFrameFileSliceFact {
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
    require_file_slice_payload(facts)?;
    let plaintext = encode_packed_inner_bundle(
        facts,
        sender_endpoint_id,
        receiver_endpoint_id,
        encode::CONNECTION_FRAME_FILE_SLICE_PLAINTEXT_BYTES,
    )?;
    let aad = encode::frame_associated_data(connection_id, nonce);
    let ciphertext =
        crypto::xchacha20poly1305_encrypt(&connection_secret, &aad, &nonce, &plaintext)?;
    encode::encode_frame_bytes(FixedBytes(connection_id), FixedBytes(nonce), &ciphertext)
        .map_err(encode::wire_err)
}

fn require_file_slice_payload(facts: &[Vec<u8>]) -> Result<(), String> {
    if facts.len() != 1 {
        return Err("connection::frame file-slice frame must carry exactly one fact".to_string());
    }
    let fact_len = facts[0].len();
    if fact_len != file_slice::encode::CONTENT_FILE_SLICE_BYTES {
        return Err(format!(
            "connection::frame file-slice payload must be {} bytes, got {fact_len}",
            file_slice::encode::CONTENT_FILE_SLICE_BYTES
        ));
    }
    Ok(())
}

fn exact_frame_slot<const N: usize>(frame: &[u8]) -> Result<FixedSlot<N>, String> {
    if frame.len() != N {
        return Err(format!("connection frame must be exactly {N} bytes"));
    }
    FixedSlot::new(frame).map_err(|err| format!("connection frame bytes: {err}"))
}

fn inner_bundle_packed_len(facts: &[Vec<u8>]) -> Result<usize, String> {
    if facts.is_empty() {
        return Err("connection::frame inner bundle must contain at least one fact".to_string());
    }
    let mut len = INNER_BUNDLE_HEADER_BYTES;
    for fact in facts {
        let fact_len = fact.len();
        u32::try_from(fact_len)
            .map_err(|_| format!("connection::frame inner length too large: {fact_len}"))?;
        len = len
            .checked_add(INNER_FACT_LEN_BYTES)
            .and_then(|len| len.checked_add(fact_len))
            .ok_or_else(|| "connection::frame inner bundle length overflow".to_string())?;
    }
    Ok(len)
}

fn encode_packed_inner_bundle(
    facts: &[Vec<u8>],
    sender_endpoint_id: FactId,
    receiver_endpoint_id: FactId,
    plaintext_len: usize,
) -> Result<Vec<u8>, String> {
    let packed_len = inner_bundle_packed_len(facts)?;
    if packed_len > plaintext_len {
        return Err(format!(
            "connection::frame inner payload too large: max {} got {packed_len}",
            plaintext_len
        ));
    }

    let mut out = vec![0; plaintext_len];
    let mut offset = 0;
    put(&mut out, &mut offset, INNER_BUNDLE_TAG)?;
    put(&mut out, &mut offset, &[INNER_BUNDLE_VERSION])?;
    put(&mut out, &mut offset, &sender_endpoint_id)?;
    put(&mut out, &mut offset, &receiver_endpoint_id)?;
    put_u32(&mut out, &mut offset, facts.len())?;
    for fact in facts {
        put_u32(&mut out, &mut offset, fact.len())?;
        put(&mut out, &mut offset, fact)?;
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
