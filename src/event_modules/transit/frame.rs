//! Transit frame crypto and inner-bundle framing.

use crate::core::crypto::{self, XChaCha20Poly1305Nonce};
use crate::core::facts::FactId;
use crate::core::wire::{FixedBytes, WireError};

use super::layout::{
    self, TRANSIT_FRAME_SIZE_CLASS_LARGE, TRANSIT_FRAME_SIZE_CLASS_SMALL,
    TRANSIT_LARGE_PLAINTEXT_BYTES, TRANSIT_SMALL_PLAINTEXT_BYTES,
};

const FRAME_PURPOSE: &[u8] = b"topo transit frame v1";
const INNER_BUNDLE_TAG: &[u8; 4] = b"TIB1";
const INNER_BUNDLE_VERSION: u8 = 1;

#[derive(Debug, Clone)]
pub struct SealConnectionFrame {
    pub connection_id: FactId,
    pub sender_endpoint_id: FactId,
    pub receiver_endpoint_id: FactId,
    pub connection_secret: crypto::XChaCha20Poly1305Key,
    pub nonce: XChaCha20Poly1305Nonce,
    pub facts: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedConnectionFrame {
    pub connection_id: FactId,
    pub sender_endpoint_id: FactId,
    pub receiver_endpoint_id: FactId,
    pub frame_hash: [u8; 32],
    pub facts: Vec<Vec<u8>>,
}

pub fn received_connection_fact_id(frame: &[u8]) -> Result<FactId, String> {
    Ok(layout::decode_frame_parts(frame)
        .map_err(wire_err)?
        .header
        .connection_id
        .0)
}

pub fn seal_connection_frame(input: SealConnectionFrame) -> Result<Vec<u8>, String> {
    let plaintext = encode_inner_bundle(&input.facts)?;
    let size_class = frame_size_class_for_plaintext(plaintext.len())?;
    let aad = frame_associated_data(
        size_class,
        input.sender_endpoint_id,
        input.receiver_endpoint_id,
        input.connection_id,
        input.nonce,
    );
    let ciphertext = crypto::xchacha20poly1305_encrypt(
        &input.connection_secret,
        &aad,
        &input.nonce,
        &plaintext,
    )?;
    layout::encode_frame_bytes(
        size_class,
        FixedBytes(input.sender_endpoint_id),
        FixedBytes(input.receiver_endpoint_id),
        FixedBytes(input.connection_id),
        FixedBytes(input.nonce),
        &ciphertext,
    )
    .map_err(wire_err)
}

pub fn open_connection_frame(
    frame: &[u8],
    connection_secret: &crypto::XChaCha20Poly1305Key,
) -> Result<OpenedConnectionFrame, String> {
    let parts = layout::decode_frame_parts(frame).map_err(wire_err)?;
    let aad = frame_associated_data(
        parts.header.size_class,
        parts.header.sender_endpoint_id.0,
        parts.header.receiver_endpoint_id.0,
        parts.header.connection_id.0,
        parts.header.nonce.0,
    );
    let plaintext = crypto::xchacha20poly1305_decrypt(
        connection_secret,
        &aad,
        &parts.header.nonce.0,
        parts.ciphertext,
    )?;
    Ok(OpenedConnectionFrame {
        connection_id: parts.header.connection_id.0,
        sender_endpoint_id: parts.header.sender_endpoint_id.0,
        receiver_endpoint_id: parts.header.receiver_endpoint_id.0,
        frame_hash: crypto::hash(frame),
        facts: decode_inner_bundle(&plaintext)?,
    })
}

fn frame_size_class_for_plaintext(len: usize) -> Result<u8, String> {
    if len <= TRANSIT_SMALL_PLAINTEXT_BYTES {
        Ok(TRANSIT_FRAME_SIZE_CLASS_SMALL)
    } else if len <= TRANSIT_LARGE_PLAINTEXT_BYTES {
        Ok(TRANSIT_FRAME_SIZE_CLASS_LARGE)
    } else {
        Err(format!(
            "transit inner payload too large: max {} got {len}",
            TRANSIT_LARGE_PLAINTEXT_BYTES
        ))
    }
}

fn frame_associated_data(
    size_class: u8,
    sender_endpoint_id: FactId,
    receiver_endpoint_id: FactId,
    connection_id: FactId,
    nonce: XChaCha20Poly1305Nonce,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_PURPOSE.len() + 1 + 32 * 3 + 24);
    out.extend_from_slice(FRAME_PURPOSE);
    out.push(size_class);
    out.extend_from_slice(&sender_endpoint_id);
    out.extend_from_slice(&receiver_endpoint_id);
    out.extend_from_slice(&connection_id);
    out.extend_from_slice(&nonce);
    out
}

fn encode_inner_bundle(facts: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    if facts.is_empty() {
        return Err("transit inner bundle must contain at least one fact".to_string());
    }
    let mut out = Vec::new();
    out.extend_from_slice(INNER_BUNDLE_TAG);
    out.push(INNER_BUNDLE_VERSION);
    push_u32(&mut out, facts.len())?;
    for fact in facts {
        push_u32(&mut out, fact.len())?;
        out.extend_from_slice(fact);
    }
    Ok(out)
}

fn decode_inner_bundle(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let mut reader = Reader::new(bytes);
    if reader.take(4)? != INNER_BUNDLE_TAG {
        return Err("expected transit inner bundle".to_string());
    }
    let version = reader.u8()?;
    if version != INNER_BUNDLE_VERSION {
        return Err(format!(
            "unsupported transit inner bundle version {version}"
        ));
    }
    let count = reader.u32()? as usize;
    if count == 0 {
        return Err("transit inner bundle must contain at least one fact".to_string());
    }
    let mut facts = Vec::with_capacity(count);
    for _ in 0..count {
        facts.push(reader.bytes()?.to_vec());
    }
    reader.finish()?;
    Ok(facts)
}

fn push_u32(out: &mut Vec<u8>, value: usize) -> Result<(), String> {
    let value =
        u32::try_from(value).map_err(|_| format!("transit inner length too large: {value}"))?;
    out.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn wire_err(err: WireError) -> String {
    format!("{err:?}")
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn bytes(&mut self) -> Result<&'a [u8], String> {
        let len = self.u32()? as usize;
        self.take(len)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| "transit inner bundle length overflow".to_string())?;
        if end > self.bytes.len() {
            return Err("truncated transit inner bundle".to_string());
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn finish(self) -> Result<(), String> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err("transit inner bundle has trailing bytes".to_string())
        }
    }
}
