//! Transit frame crypto and inner-bundle framing.
//!
//! Transport sends exact facts inside encrypted connection frames. This module
//! packs fact bytes into a canonical inner bundle, chooses a fixed frame size
//! class, binds the connection and endpoint ids as associated data, and opens
//! frames back into fact bundles for submission.
//!
//! Keep per-frame cryptographic mechanics here. Connection facts provide the
//! shared secret, send intents decide which facts to bundle, and received
//! transit projection records provenance after a frame has been opened.

use crate::core::crypto::{self, XChaCha20Poly1305Nonce};
use crate::core::facts::FactId;
use crate::core::wire::{FixedBytes, WireError};

use super::layout::{
    self, TRANSIT_FRAME_SIZE_CLASS_LARGE, TRANSIT_FRAME_SIZE_CLASS_SMALL,
    TRANSIT_LARGE_CIPHERTEXT_BYTES, TRANSIT_LARGE_PLAINTEXT_BYTES, TRANSIT_SMALL_CIPHERTEXT_BYTES,
    TRANSIT_SMALL_PLAINTEXT_BYTES,
};

const FRAME_PURPOSE: &[u8] = b"topo transport::transit frame v1";
const INNER_BUNDLE_TAG: &[u8; 4] = b"TIB1";
const INNER_BUNDLE_VERSION: u8 = 1;
const INNER_BUNDLE_HEADER_BYTES: usize = 4 + 1 + 4;
const INNER_FACT_LEN_BYTES: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TransitFactBundle {
    facts: Vec<TransitFactBytes>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TransitFactBytes {
    bytes: Vec<u8>,
}

impl TransitFactBundle {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_bytes(bytes: impl IntoIterator<Item = Vec<u8>>) -> Self {
        let mut bundle = Self::new();
        for bytes in bytes {
            bundle.push(bytes);
        }
        bundle
    }

    pub fn push(&mut self, bytes: Vec<u8>) {
        self.facts.push(TransitFactBytes { bytes });
    }

    pub fn len(&self) -> usize {
        self.facts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &[u8]> {
        self.facts.iter().map(|fact| fact.bytes.as_slice())
    }
}

impl IntoIterator for TransitFactBundle {
    type Item = Vec<u8>;
    type IntoIter = TransitFactBundleIntoIter;

    fn into_iter(self) -> Self::IntoIter {
        TransitFactBundleIntoIter {
            inner: self.facts.into_iter(),
        }
    }
}

pub struct TransitFactBundleIntoIter {
    inner: std::vec::IntoIter<TransitFactBytes>,
}

impl Iterator for TransitFactBundleIntoIter {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|fact| fact.bytes)
    }
}

#[derive(Debug, Clone)]
pub struct SealConnectionFrame {
    pub connection_id: FactId,
    pub sender_endpoint_id: FactId,
    pub receiver_endpoint_id: FactId,
    pub connection_secret: crypto::XChaCha20Poly1305Key,
    pub nonce: XChaCha20Poly1305Nonce,
    pub facts: TransitFactBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedConnectionFrame {
    pub connection_id: FactId,
    pub sender_endpoint_id: FactId,
    pub receiver_endpoint_id: FactId,
    pub frame_hash: [u8; 32],
    pub facts: TransitFactBundle,
}

pub fn connection_send_nonce(connection_id: FactId, fact_ids: &[FactId]) -> XChaCha20Poly1305Nonce {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:transport::transit-connection-send-nonce:v1:");
    hash.update(&connection_id);
    hash.update(&(fact_ids.len() as u32).to_be_bytes());
    for fact_id in fact_ids {
        hash.update(fact_id);
    }
    let digest = hash.finalize();
    let mut nonce = [0; 24];
    nonce.copy_from_slice(&digest.as_bytes()[..24]);
    nonce
}

pub fn received_connection_fact_id(frame: &[u8]) -> Result<FactId, String> {
    Ok(layout::decode_frame_parts(frame)
        .map_err(wire_err)?
        .header
        .connection_id
        .0)
}

pub fn seal_connection_frame(input: SealConnectionFrame) -> Result<Vec<u8>, String> {
    let packed_len = inner_bundle_packed_len(&input.facts)?;
    let size_class = frame_size_class_for_plaintext(packed_len)?;
    let plaintext = encode_inner_bundle(&input.facts, plaintext_len_for_size_class(size_class)?)?;
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

pub fn seal_connection_send_frame(
    connection_id: FactId,
    sender_endpoint_id: FactId,
    receiver_endpoint_id: FactId,
    connection_secret: crypto::XChaCha20Poly1305Key,
    fact_ids: &[FactId],
    facts: TransitFactBundle,
) -> Result<Vec<u8>, String> {
    seal_connection_frame(SealConnectionFrame {
        connection_id,
        sender_endpoint_id,
        receiver_endpoint_id,
        connection_secret,
        nonce: connection_send_nonce(connection_id, fact_ids),
        facts,
    })
}

pub fn open_connection_frame(
    frame: &[u8],
    connection_secret: &crypto::XChaCha20Poly1305Key,
) -> Result<OpenedConnectionFrame, String> {
    let parts = layout::decode_frame_parts(frame).map_err(wire_err)?;
    let expected_ciphertext_len = ciphertext_len_for_size_class(parts.header.size_class)?;
    if parts.ciphertext.len() != expected_ciphertext_len {
        return Err(format!(
            "transport::transit frame ciphertext must fill fixed slot: expected {} got {}",
            expected_ciphertext_len,
            parts.ciphertext.len()
        ));
    }
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
    let expected_plaintext_len = plaintext_len_for_size_class(parts.header.size_class)?;
    if plaintext.len() != expected_plaintext_len {
        return Err(format!(
            "transport::transit frame plaintext must fill fixed slot: expected {} got {}",
            expected_plaintext_len,
            plaintext.len()
        ));
    }
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
            "transport::transit inner payload too large: max {} got {len}",
            TRANSIT_LARGE_PLAINTEXT_BYTES
        ))
    }
}

fn plaintext_len_for_size_class(size_class: u8) -> Result<usize, String> {
    match size_class {
        TRANSIT_FRAME_SIZE_CLASS_SMALL => Ok(TRANSIT_SMALL_PLAINTEXT_BYTES),
        TRANSIT_FRAME_SIZE_CLASS_LARGE => Ok(TRANSIT_LARGE_PLAINTEXT_BYTES),
        other => Err(format!(
            "unknown transport::transit frame size class {other}"
        )),
    }
}

fn ciphertext_len_for_size_class(size_class: u8) -> Result<usize, String> {
    match size_class {
        TRANSIT_FRAME_SIZE_CLASS_SMALL => Ok(TRANSIT_SMALL_CIPHERTEXT_BYTES),
        TRANSIT_FRAME_SIZE_CLASS_LARGE => Ok(TRANSIT_LARGE_CIPHERTEXT_BYTES),
        other => Err(format!(
            "unknown transport::transit frame size class {other}"
        )),
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

fn inner_bundle_packed_len(facts: &TransitFactBundle) -> Result<usize, String> {
    if facts.is_empty() {
        return Err("transport::transit inner bundle must contain at least one fact".to_string());
    }
    let mut len = INNER_BUNDLE_HEADER_BYTES;
    for fact in facts.iter() {
        let fact_len = fact.len();
        u32::try_from(fact_len)
            .map_err(|_| format!("transport::transit inner length too large: {fact_len}"))?;
        len = len
            .checked_add(INNER_FACT_LEN_BYTES)
            .and_then(|len| len.checked_add(fact_len))
            .ok_or_else(|| "transport::transit inner bundle length overflow".to_string())?;
    }
    Ok(len)
}

fn encode_inner_bundle(facts: &TransitFactBundle, plaintext_len: usize) -> Result<Vec<u8>, String> {
    let packed_len = inner_bundle_packed_len(facts)?;
    if packed_len > plaintext_len {
        return Err(format!(
            "transport::transit inner payload too large: max {} got {packed_len}",
            plaintext_len
        ));
    }

    let mut out = vec![0; plaintext_len];
    let mut offset = 0;
    put(&mut out, &mut offset, INNER_BUNDLE_TAG)?;
    put(&mut out, &mut offset, &[INNER_BUNDLE_VERSION])?;
    put_u32(&mut out, &mut offset, facts.len())?;
    for fact in facts.iter() {
        put_u32(&mut out, &mut offset, fact.len())?;
        put(&mut out, &mut offset, fact)?;
    }
    Ok(out)
}

fn decode_inner_bundle(bytes: &[u8]) -> Result<TransitFactBundle, String> {
    let mut reader = Reader::new(bytes);
    if reader.take(4)? != INNER_BUNDLE_TAG {
        return Err("expected transport::transit inner bundle".to_string());
    }
    let version = reader.u8()?;
    if version != INNER_BUNDLE_VERSION {
        return Err(format!(
            "unsupported transport::transit inner bundle version {version}"
        ));
    }
    let count = reader.u32()? as usize;
    if count == 0 {
        return Err("transport::transit inner bundle must contain at least one fact".to_string());
    }
    let mut facts = TransitFactBundle::new();
    for _ in 0..count {
        facts.push(reader.bytes()?.to_vec());
    }
    reader.finish_zero_padding()?;
    Ok(facts)
}

fn put_u32(out: &mut [u8], offset: &mut usize, value: usize) -> Result<(), String> {
    let value = u32::try_from(value)
        .map_err(|_| format!("transport::transit inner length too large: {value}"))?;
    put(out, offset, &value.to_be_bytes())
}

fn put(out: &mut [u8], offset: &mut usize, bytes: &[u8]) -> Result<(), String> {
    let end = offset
        .checked_add(bytes.len())
        .ok_or_else(|| "transport::transit inner bundle length overflow".to_string())?;
    if end > out.len() {
        return Err("transport::transit inner bundle exceeds fixed slot".to_string());
    }
    out[*offset..end].copy_from_slice(bytes);
    *offset = end;
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
            .ok_or_else(|| "transport::transit inner bundle length overflow".to_string())?;
        if end > self.bytes.len() {
            return Err("truncated transport::transit inner bundle".to_string());
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn finish_zero_padding(self) -> Result<(), String> {
        if self.bytes[self.offset..].iter().all(|byte| *byte == 0) {
            Ok(())
        } else {
            Err("transport::transit inner bundle has nonzero padding".to_string())
        }
    }
}
