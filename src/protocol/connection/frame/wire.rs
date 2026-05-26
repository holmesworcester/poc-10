//! Fixed wire layout for encrypted connection frames.
//!
//! Connection frames have three outer shapes: small control frames, file-slice
//! frames sized for one content file-slice fact, and bundle frames sized for
//! many padded fixed fact slots. They share a public header containing tag,
//! version, size class, connection id, and nonce; only the encrypted payload
//! slot capacity differs. Sender/receiver endpoint ids are carried inside the
//! encrypted inner bundle.
//!
//! This file owns byte compatibility, size-class constants, AEAD associated
//! data, nonce derivation, and inner-bundle packing. It does not decide which
//! semantic facts are allowed to travel or whether an opened child fact is
//! valid; those checks live in `create.rs` and the child fact projectors.

use crate::core::crypto::{
    self, XChaCha20Poly1305Nonce, XCHACHA20_POLY1305_NONCE_BYTES, XCHACHA20_POLY1305_TAG_BYTES,
};
use crate::core::facts::FactId;
use crate::core::wire::{
    self, fixed_tag, Ciphertext, FixedBytes, FixedLayout, Id32, Nonce24, Tag, WireError,
};

use crate::protocol::connection::fact_receipt::create::normalize_origin_addr_bytes;
use crate::protocol::connection::fact_receipt::fact::{OriginAddr, ORIGIN_ADDR_BYTES};
use crate::protocol::content::{file, file_slice};

/// Public tag prefix shared by all connection::frame frame variants.
pub const CONNECTION_FRAME_TAG: Tag<4> = fixed_tag(b"TRNS");

/// Current connection::frame frame version.
pub const CONNECTION_FRAME_VERSION: u8 = 1;

/// Size class byte for [`ConnectionFrameSmallV1`].
pub const CONNECTION_FRAME_SIZE_CLASS_SMALL: u8 = 0;

/// Size class byte for [`ConnectionFrameFileSliceV1`].
pub const CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE: u8 = 1;

/// Size class byte for [`ConnectionFrameBundleV1`].
pub const CONNECTION_FRAME_SIZE_CLASS_BUNDLE: u8 = 2;

/// Plaintext capacity of a small connection::frame frame (4 KiB).
///
/// Small frames carry control traffic and single facts; the batcher chooses
/// this class when the packed inner bytes fit in the small budget.
pub const CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES: usize = 4 * 1024;

/// Plaintext capacity of a file-slice connection::frame frame.
///
/// This capacity is exactly one inner-bundle header plus one length-prefixed
/// content file-slice fact. It avoids the old 1 MiB catch-all frame while still
/// carrying a full `content::file_slice`.
pub const CONNECTION_FRAME_FILE_SLICE_PLAINTEXT_BYTES: usize =
    INNER_BUNDLE_HEADER_BYTES + INNER_FACT_LEN_BYTES + file_slice::layout::CONTENT_FILE_SLICE_BYTES;

/// Maximum fact bytes carried in one padded bundle slot.
///
/// The current maximum non-file-slice carrier is a content-file payload. If a
/// future non-slice fact grows, the guardrail test should force this constant
/// to move with it.
pub const CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES: usize = file::layout::CONTENT_FILE_BYTES;

/// Number of padded fact slots in one bundle frame.
///
/// This is the maximum slot count that keeps the encrypted plaintext below
/// 64 KiB while fitting the current largest normal fact in every slot.
pub const CONNECTION_FRAME_BUNDLE_FACT_SLOTS: usize = (64 * 1024 - INNER_BUNDLE_HEADER_BYTES)
    / (INNER_FACT_LEN_BYTES + CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES);

/// Plaintext capacity of a bundled connection::frame frame.
pub const CONNECTION_FRAME_BUNDLE_PLAINTEXT_BYTES: usize = INNER_BUNDLE_HEADER_BYTES
    + CONNECTION_FRAME_BUNDLE_FACT_SLOTS
        * (INNER_FACT_LEN_BYTES + CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES);

/// Ciphertext slot capacity for small frames (plaintext + AEAD tag).
pub const CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES: usize =
    CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;

/// Ciphertext slot capacity for file-slice frames (plaintext + AEAD tag).
pub const CONNECTION_FRAME_FILE_SLICE_CIPHERTEXT_BYTES: usize =
    CONNECTION_FRAME_FILE_SLICE_PLAINTEXT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;

/// Ciphertext slot capacity for bundle frames (plaintext + AEAD tag).
pub const CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES: usize =
    CONNECTION_FRAME_BUNDLE_PLAINTEXT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;

/// Fixed public header size (tag + version + size class + connection id + nonce).
pub const CONNECTION_FRAME_HEADER_BYTES: usize =
    Tag::<4>::LEN + wire::U8_BYTES + wire::U8_BYTES + Id32::LEN + Nonce24::LEN;

/// Outer wire length for a [`ConnectionFrameSmallV1`] frame.
pub const CONNECTION_FRAME_SMALL_WIRE_BYTES: usize =
    CONNECTION_FRAME_HEADER_BYTES + Ciphertext::<CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES>::LEN;

/// Outer wire length for a [`ConnectionFrameFileSliceV1`] frame.
pub const CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES: usize =
    CONNECTION_FRAME_HEADER_BYTES + Ciphertext::<CONNECTION_FRAME_FILE_SLICE_CIPHERTEXT_BYTES>::LEN;

/// Outer wire length for a [`ConnectionFrameBundleV1`] frame.
pub const CONNECTION_FRAME_BUNDLE_WIRE_BYTES: usize =
    CONNECTION_FRAME_HEADER_BYTES + Ciphertext::<CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES>::LEN;

const VERSION_OFFSET: usize = Tag::<4>::LEN;
const SIZE_CLASS_OFFSET: usize = VERSION_OFFSET + wire::U8_BYTES;
const CONNECTION_OFFSET: usize = SIZE_CLASS_OFFSET + wire::U8_BYTES;
const NONCE_OFFSET: usize = CONNECTION_OFFSET + Id32::LEN;
const CIPHERTEXT_OFFSET: usize = NONCE_OFFSET + Nonce24::LEN;

pub const fn received_frame_fact_bytes<const FRAME_BYTES: usize>() -> usize {
    1 + wire::FixedSlot::<ORIGIN_ADDR_BYTES>::LEN + 8 + wire::FixedSlot::<FRAME_BYTES>::LEN
}

pub fn encode_received_frame_fact<const FRAME_BYTES: usize>(
    tag: u8,
    expected_size_class: u8,
    origin_addr: &OriginAddr,
    received_at_local_ms: u64,
    frame: &wire::FixedSlot<FRAME_BYTES>,
) -> Result<Vec<u8>, String> {
    if frame.len() != FRAME_BYTES {
        return Err(format!(
            "connection frame fact bytes must be {FRAME_BYTES} bytes"
        ));
    }
    require_frame_size_class(frame.bytes(), expected_size_class)?;
    let origin_addr = normalize_origin_addr_bytes(origin_addr.bytes())?;
    let origin_addr = OriginAddr::new(&origin_addr).map_err(wire_err)?;
    let mut out = wire::Writer::with_capacity(received_frame_fact_bytes::<FRAME_BYTES>());
    out.u8(tag);
    out.fixed_slot_value(&origin_addr).map_err(wire_err)?;
    out.u64be(received_at_local_ms);
    out.fixed_slot_value(frame).map_err(wire_err)?;
    out.finish_exact(received_frame_fact_bytes::<FRAME_BYTES>())
        .map_err(wire_err)
}

pub fn decode_received_frame_fact<const FRAME_BYTES: usize>(
    bytes: &[u8],
    tag: u8,
    expected_size_class: u8,
) -> Result<(OriginAddr, u64, wire::FixedSlot<FRAME_BYTES>), String> {
    let mut reader = wire::Reader::new(bytes);
    reader
        .expect_len(received_frame_fact_bytes::<FRAME_BYTES>())
        .map_err(wire_err)?;
    reader.expect_u8(tag).map_err(wire_err)?;
    let origin_addr = reader
        .fixed_slot_value::<ORIGIN_ADDR_BYTES>()
        .map_err(wire_err)?;
    let canonical_origin_addr = normalize_origin_addr_bytes(origin_addr.bytes())?;
    if canonical_origin_addr != origin_addr.bytes() {
        return Err("connection frame origin addr is not canonical".to_string());
    }
    let received_at_local_ms = reader.u64be().map_err(wire_err)?;
    let frame = reader.fixed_slot_value::<FRAME_BYTES>().map_err(wire_err)?;
    reader.finish().map_err(wire_err)?;
    require_frame_size_class(frame.bytes(), expected_size_class)?;
    if frame.len() != FRAME_BYTES {
        return Err("connection frame fact slot must be full".to_string());
    }
    Ok((origin_addr, received_at_local_ms, frame))
}

fn require_frame_size_class(frame: &[u8], expected_size_class: u8) -> Result<(), String> {
    let parts = decode_frame_parts(frame).map_err(wire_err)?;
    if parts.header.size_class != expected_size_class {
        return Err(format!(
            "connection frame fact size class mismatch: expected {} got {}",
            expected_size_class, parts.header.size_class
        ));
    }
    Ok(())
}

/// Fixed-width small connection::frame frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFrameSmallV1 {
    pub connection_id: Id32,
    pub nonce: Nonce24,
    pub ciphertext: Ciphertext<CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES>,
}

/// Fixed-width file-slice connection::frame frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFrameFileSliceV1 {
    pub connection_id: Id32,
    pub nonce: Nonce24,
    pub ciphertext: Ciphertext<CONNECTION_FRAME_FILE_SLICE_CIPHERTEXT_BYTES>,
}

/// Fixed-width bundled connection::frame frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFrameBundleV1 {
    pub connection_id: Id32,
    pub nonce: Nonce24,
    pub ciphertext: Ciphertext<CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES>,
}

impl FixedLayout for ConnectionFrameSmallV1 {
    const LEN: usize = CONNECTION_FRAME_SMALL_WIRE_BYTES;

    fn encode(&self, out: &mut [u8]) -> Result<(), WireError> {
        encode_header(
            out,
            Self::LEN,
            CONNECTION_FRAME_SIZE_CLASS_SMALL,
            &self.connection_id,
            &self.nonce,
        )?;
        self.ciphertext.encode(&mut out[CIPHERTEXT_OFFSET..])
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let (connection, nonce) =
            decode_header(bytes, Self::LEN, CONNECTION_FRAME_SIZE_CLASS_SMALL)?;
        let ciphertext = Ciphertext::<CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES>::decode(
            &bytes[CIPHERTEXT_OFFSET..],
        )?;
        Ok(Self {
            connection_id: connection,
            nonce,
            ciphertext,
        })
    }
}

impl FixedLayout for ConnectionFrameFileSliceV1 {
    const LEN: usize = CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES;

    fn encode(&self, out: &mut [u8]) -> Result<(), WireError> {
        encode_header(
            out,
            Self::LEN,
            CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE,
            &self.connection_id,
            &self.nonce,
        )?;
        self.ciphertext.encode(&mut out[CIPHERTEXT_OFFSET..])
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let (connection, nonce) =
            decode_header(bytes, Self::LEN, CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE)?;
        let ciphertext = Ciphertext::<CONNECTION_FRAME_FILE_SLICE_CIPHERTEXT_BYTES>::decode(
            &bytes[CIPHERTEXT_OFFSET..],
        )?;
        Ok(Self {
            connection_id: connection,
            nonce,
            ciphertext,
        })
    }
}

impl FixedLayout for ConnectionFrameBundleV1 {
    const LEN: usize = CONNECTION_FRAME_BUNDLE_WIRE_BYTES;

    fn encode(&self, out: &mut [u8]) -> Result<(), WireError> {
        encode_header(
            out,
            Self::LEN,
            CONNECTION_FRAME_SIZE_CLASS_BUNDLE,
            &self.connection_id,
            &self.nonce,
        )?;
        self.ciphertext.encode(&mut out[CIPHERTEXT_OFFSET..])
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let (connection, nonce) =
            decode_header(bytes, Self::LEN, CONNECTION_FRAME_SIZE_CLASS_BUNDLE)?;
        let ciphertext = Ciphertext::<CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES>::decode(
            &bytes[CIPHERTEXT_OFFSET..],
        )?;
        Ok(Self {
            connection_id: connection,
            nonce,
            ciphertext,
        })
    }
}

/// Public header view recovered without decrypting the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFrameHeader {
    pub size_class: u8,
    pub connection_id: Id32,
    pub nonce: Nonce24,
}

/// Borrowed connection::frame frame payload recovered without materializing a
/// large fixed-slot value on the stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFrameParts<'a> {
    pub header: ConnectionFrameHeader,
    pub ciphertext: &'a [u8],
}

/// Inspect just the public header of a connection::frame frame.
///
/// Returns the size class byte and addressing fields. The caller decides which
/// of the fixed frame decoders to run based on `size_class` and the outer
/// length.
pub fn peek_frame_header(bytes: &[u8]) -> Result<ConnectionFrameHeader, WireError> {
    if bytes.len() < CONNECTION_FRAME_HEADER_BYTES {
        return Err(WireError::WrongLength {
            expected: CONNECTION_FRAME_HEADER_BYTES,
            actual: bytes.len(),
        });
    }
    let tag = Tag::<4>::decode(&bytes[..VERSION_OFFSET])?;
    if tag != CONNECTION_FRAME_TAG {
        return Err(WireError::NonZeroPadding { index: 0 });
    }
    let version = wire::take_u8(&bytes[VERSION_OFFSET..SIZE_CLASS_OFFSET])?;
    if version != CONNECTION_FRAME_VERSION {
        return Err(WireError::InvalidBool { actual: version });
    }
    let size_class = wire::take_u8(&bytes[SIZE_CLASS_OFFSET..CONNECTION_OFFSET])?;
    let connection_id = Id32::decode(&bytes[CONNECTION_OFFSET..NONCE_OFFSET])?;
    let nonce = Nonce24::decode(&bytes[NONCE_OFFSET..CIPHERTEXT_OFFSET])?;
    Ok(ConnectionFrameHeader {
        size_class,
        connection_id,
        nonce,
    })
}

/// Decode the public header and borrowed ciphertext slot for any size class
/// without copying the full padded payload.
pub fn decode_frame_parts(bytes: &[u8]) -> Result<ConnectionFrameParts<'_>, WireError> {
    let header = peek_frame_header(bytes)?;
    let (expected_len, capacity) = frame_shape(header.size_class)?;
    if bytes.len() != expected_len {
        return Err(WireError::WrongLength {
            expected: expected_len,
            actual: bytes.len(),
        });
    }
    let slot = &bytes[CIPHERTEXT_OFFSET..];
    let ciphertext_len = wire::take_u32be(&slot[..4])? as usize;
    if ciphertext_len > capacity {
        return Err(WireError::ValueTooLarge {
            max: capacity,
            actual: ciphertext_len,
        });
    }
    if let Some(offset) = slot[4 + ciphertext_len..]
        .iter()
        .position(|byte| *byte != 0)
    {
        return Err(WireError::NonZeroPadding {
            index: CIPHERTEXT_OFFSET + 4 + ciphertext_len + offset,
        });
    }
    Ok(ConnectionFrameParts {
        header,
        ciphertext: &slot[4..4 + ciphertext_len],
    })
}

/// Encode a connection::frame frame for any size class from already-encrypted bytes.
pub fn encode_frame_bytes(
    size_class: u8,
    connection_id: Id32,
    nonce: Nonce24,
    ciphertext: &[u8],
) -> Result<Vec<u8>, WireError> {
    let (wire_len, capacity) = frame_shape(size_class)?;
    if ciphertext.len() > capacity {
        return Err(WireError::ValueTooLarge {
            max: capacity,
            actual: ciphertext.len(),
        });
    }
    let mut out = vec![0; wire_len];
    encode_header(&mut out, wire_len, size_class, &connection_id, &nonce)?;
    wire::put_u32be(
        ciphertext.len() as u32,
        &mut out[CIPHERTEXT_OFFSET..CIPHERTEXT_OFFSET + 4],
    )?;
    out[CIPHERTEXT_OFFSET + 4..CIPHERTEXT_OFFSET + 4 + ciphertext.len()]
        .copy_from_slice(ciphertext);
    Ok(out)
}

fn encode_header(
    out: &mut [u8],
    expected_len: usize,
    size_class: u8,
    connection: &Id32,
    nonce: &Nonce24,
) -> Result<(), WireError> {
    if out.len() != expected_len {
        return Err(WireError::WrongLength {
            expected: expected_len,
            actual: out.len(),
        });
    }
    CONNECTION_FRAME_TAG.encode(&mut out[..VERSION_OFFSET])?;
    wire::put_u8(
        CONNECTION_FRAME_VERSION,
        &mut out[VERSION_OFFSET..SIZE_CLASS_OFFSET],
    )?;
    wire::put_u8(size_class, &mut out[SIZE_CLASS_OFFSET..CONNECTION_OFFSET])?;
    connection.encode(&mut out[CONNECTION_OFFSET..NONCE_OFFSET])?;
    nonce.encode(&mut out[NONCE_OFFSET..CIPHERTEXT_OFFSET])?;
    Ok(())
}

fn decode_header(
    bytes: &[u8],
    expected_len: usize,
    expected_size_class: u8,
) -> Result<(Id32, Nonce24), WireError> {
    if bytes.len() != expected_len {
        return Err(WireError::WrongLength {
            expected: expected_len,
            actual: bytes.len(),
        });
    }
    let tag = Tag::<4>::decode(&bytes[..VERSION_OFFSET])?;
    if tag != CONNECTION_FRAME_TAG {
        return Err(WireError::NonZeroPadding { index: 0 });
    }
    let version = wire::take_u8(&bytes[VERSION_OFFSET..SIZE_CLASS_OFFSET])?;
    if version != CONNECTION_FRAME_VERSION {
        return Err(WireError::InvalidBool { actual: version });
    }
    let size_class = wire::take_u8(&bytes[SIZE_CLASS_OFFSET..CONNECTION_OFFSET])?;
    if size_class != expected_size_class {
        return Err(WireError::InvalidBool { actual: size_class });
    }
    let connection = Id32::decode(&bytes[CONNECTION_OFFSET..NONCE_OFFSET])?;
    let nonce = Nonce24::decode(&bytes[NONCE_OFFSET..CIPHERTEXT_OFFSET])?;
    Ok((connection, nonce))
}

fn frame_shape(size_class: u8) -> Result<(usize, usize), WireError> {
    match size_class {
        CONNECTION_FRAME_SIZE_CLASS_SMALL => Ok((
            CONNECTION_FRAME_SMALL_WIRE_BYTES,
            CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES,
        )),
        CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE => Ok((
            CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES,
            CONNECTION_FRAME_FILE_SLICE_CIPHERTEXT_BYTES,
        )),
        CONNECTION_FRAME_SIZE_CLASS_BUNDLE => Ok((
            CONNECTION_FRAME_BUNDLE_WIRE_BYTES,
            CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES,
        )),
        other => Err(WireError::InvalidBool { actual: other }),
    }
}

/// Sanity-check assertion that the constants above stay consistent.
const _: () = {
    assert!(CONNECTION_FRAME_HEADER_BYTES == 4 + 1 + 1 + 32 + XCHACHA20_POLY1305_NONCE_BYTES);
    assert!(CONNECTION_FRAME_SMALL_WIRE_BYTES < CONNECTION_FRAME_BUNDLE_WIRE_BYTES);
    assert!(CONNECTION_FRAME_BUNDLE_WIRE_BYTES < CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES);
};

// ---------------------------------------------------------------------------
// Connection-frame sealing and inner bundle helpers.
// ---------------------------------------------------------------------------

const FRAME_PURPOSE: &[u8] = b"topo connection::frame frame v1";
const INNER_BUNDLE_TAG: &[u8; 4] = b"TIB1";
const INNER_BUNDLE_VERSION: u8 = 1;
const INNER_BUNDLE_HEADER_BYTES: usize = 4 + 1 + 32 + 32 + 4;
const INNER_FACT_LEN_BYTES: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ConnectionFrameFactBundle {
    facts: Vec<ConnectionFrameFactBytes>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConnectionFrameFactBytes {
    bytes: Vec<u8>,
}

impl ConnectionFrameFactBundle {
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
        self.facts.push(ConnectionFrameFactBytes { bytes });
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

impl IntoIterator for ConnectionFrameFactBundle {
    type Item = Vec<u8>;
    type IntoIter = ConnectionFrameFactBundleIntoIter;

    fn into_iter(self) -> Self::IntoIter {
        ConnectionFrameFactBundleIntoIter {
            inner: self.facts.into_iter(),
        }
    }
}

pub struct ConnectionFrameFactBundleIntoIter {
    inner: std::vec::IntoIter<ConnectionFrameFactBytes>,
}

impl Iterator for ConnectionFrameFactBundleIntoIter {
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
    pub facts: ConnectionFrameFactBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedConnectionFrame {
    pub connection_id: FactId,
    pub sender_endpoint_id: FactId,
    pub receiver_endpoint_id: FactId,
    pub frame_hash: [u8; 32],
    pub facts: ConnectionFrameFactBundle,
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

pub fn received_connection_fact_id(frame: &[u8]) -> Result<FactId, String> {
    Ok(decode_frame_parts(frame)
        .map_err(wire_err)?
        .header
        .connection_id
        .0)
}

pub fn seal_connection_frame(input: SealConnectionFrame) -> Result<Vec<u8>, String> {
    let size_class = frame_size_class_for_facts(&input.facts)?;
    let plaintext = encode_inner_bundle(
        size_class,
        &input.facts,
        input.sender_endpoint_id,
        input.receiver_endpoint_id,
    )?;
    let aad = frame_associated_data(size_class, input.connection_id, input.nonce);
    let ciphertext = crypto::xchacha20poly1305_encrypt(
        &input.connection_secret,
        &aad,
        &input.nonce,
        &plaintext,
    )?;
    encode_frame_bytes(
        size_class,
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
    facts: ConnectionFrameFactBundle,
) -> Result<Vec<u8>, String> {
    seal_connection_frame(SealConnectionFrame {
        connection_id,
        sender_endpoint_id,
        receiver_endpoint_id,
        connection_secret,
        nonce: connection_send_nonce(
            connection_id,
            sender_endpoint_id,
            receiver_endpoint_id,
            fact_ids,
        ),
        facts,
    })
}

pub fn open_connection_frame(
    frame: &[u8],
    connection_secret: &crypto::XChaCha20Poly1305Key,
) -> Result<OpenedConnectionFrame, String> {
    let parts = decode_frame_parts(frame).map_err(wire_err)?;
    let expected_ciphertext_len = ciphertext_len_for_size_class(parts.header.size_class)?;
    if parts.ciphertext.len() != expected_ciphertext_len {
        return Err(format!(
            "connection::frame frame ciphertext must fill fixed slot: expected {} got {}",
            expected_ciphertext_len,
            parts.ciphertext.len()
        ));
    }
    let aad = frame_associated_data(
        parts.header.size_class,
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
            "connection::frame frame plaintext must fill fixed slot: expected {} got {}",
            expected_plaintext_len,
            plaintext.len()
        ));
    }
    let inner = decode_inner_bundle(parts.header.size_class, &plaintext)?;
    Ok(OpenedConnectionFrame {
        connection_id: parts.header.connection_id.0,
        sender_endpoint_id: inner.sender_endpoint_id,
        receiver_endpoint_id: inner.receiver_endpoint_id,
        frame_hash: crypto::hash(frame),
        facts: inner.facts,
    })
}

fn frame_size_class_for_facts(facts: &ConnectionFrameFactBundle) -> Result<u8, String> {
    let packed_len = inner_bundle_packed_len(facts)?;
    if packed_len <= CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES {
        Ok(CONNECTION_FRAME_SIZE_CLASS_SMALL)
    } else if facts.len() == 1
        && facts
            .iter()
            .next()
            .is_some_and(|fact| fact.len() == file_slice::layout::CONTENT_FILE_SLICE_BYTES)
    {
        Ok(CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE)
    } else if facts.len() <= CONNECTION_FRAME_BUNDLE_FACT_SLOTS
        && facts
            .iter()
            .all(|fact| fact.len() <= CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES)
    {
        Ok(CONNECTION_FRAME_SIZE_CLASS_BUNDLE)
    } else {
        Err(format!(
            "connection::frame inner payload does not fit small, file-slice, or {}x{} bundle slots",
            CONNECTION_FRAME_BUNDLE_FACT_SLOTS, CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES
        ))
    }
}

fn plaintext_len_for_size_class(size_class: u8) -> Result<usize, String> {
    match size_class {
        CONNECTION_FRAME_SIZE_CLASS_SMALL => Ok(CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES),
        CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE => Ok(CONNECTION_FRAME_FILE_SLICE_PLAINTEXT_BYTES),
        CONNECTION_FRAME_SIZE_CLASS_BUNDLE => Ok(CONNECTION_FRAME_BUNDLE_PLAINTEXT_BYTES),
        other => Err(format!(
            "unknown connection::frame frame size class {other}"
        )),
    }
}

fn ciphertext_len_for_size_class(size_class: u8) -> Result<usize, String> {
    match size_class {
        CONNECTION_FRAME_SIZE_CLASS_SMALL => Ok(CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES),
        CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE => Ok(CONNECTION_FRAME_FILE_SLICE_CIPHERTEXT_BYTES),
        CONNECTION_FRAME_SIZE_CLASS_BUNDLE => Ok(CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES),
        other => Err(format!(
            "unknown connection::frame frame size class {other}"
        )),
    }
}

fn frame_associated_data(
    size_class: u8,
    connection_id: FactId,
    nonce: XChaCha20Poly1305Nonce,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_PURPOSE.len() + 1 + 32 + 24);
    out.extend_from_slice(FRAME_PURPOSE);
    out.push(size_class);
    out.extend_from_slice(&connection_id);
    out.extend_from_slice(&nonce);
    out
}

fn inner_bundle_packed_len(facts: &ConnectionFrameFactBundle) -> Result<usize, String> {
    if facts.is_empty() {
        return Err("connection::frame inner bundle must contain at least one fact".to_string());
    }
    let mut len = INNER_BUNDLE_HEADER_BYTES;
    for fact in facts.iter() {
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

fn encode_inner_bundle(
    size_class: u8,
    facts: &ConnectionFrameFactBundle,
    sender_endpoint_id: FactId,
    receiver_endpoint_id: FactId,
) -> Result<Vec<u8>, String> {
    match size_class {
        CONNECTION_FRAME_SIZE_CLASS_SMALL | CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE => {
            encode_packed_inner_bundle(
                facts,
                plaintext_len_for_size_class(size_class)?,
                sender_endpoint_id,
                receiver_endpoint_id,
            )
        }
        CONNECTION_FRAME_SIZE_CLASS_BUNDLE => {
            encode_fixed_slot_inner_bundle(facts, sender_endpoint_id, receiver_endpoint_id)
        }
        other => Err(format!(
            "unknown connection::frame frame size class {other}"
        )),
    }
}

fn encode_packed_inner_bundle(
    facts: &ConnectionFrameFactBundle,
    plaintext_len: usize,
    sender_endpoint_id: FactId,
    receiver_endpoint_id: FactId,
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
    for fact in facts.iter() {
        put_u32(&mut out, &mut offset, fact.len())?;
        put(&mut out, &mut offset, fact)?;
    }
    Ok(out)
}

fn encode_fixed_slot_inner_bundle(
    facts: &ConnectionFrameFactBundle,
    sender_endpoint_id: FactId,
    receiver_endpoint_id: FactId,
) -> Result<Vec<u8>, String> {
    if facts.is_empty() {
        return Err("connection::frame inner bundle must contain at least one fact".to_string());
    }
    if facts.len() > CONNECTION_FRAME_BUNDLE_FACT_SLOTS {
        return Err(format!(
            "connection::frame bundle has {} facts, max {}",
            facts.len(),
            CONNECTION_FRAME_BUNDLE_FACT_SLOTS
        ));
    }

    let mut out = vec![0; CONNECTION_FRAME_BUNDLE_PLAINTEXT_BYTES];
    let mut offset = 0;
    put(&mut out, &mut offset, INNER_BUNDLE_TAG)?;
    put(&mut out, &mut offset, &[INNER_BUNDLE_VERSION])?;
    put(&mut out, &mut offset, &sender_endpoint_id)?;
    put(&mut out, &mut offset, &receiver_endpoint_id)?;
    put_u32(&mut out, &mut offset, facts.len())?;
    for fact in facts.iter() {
        if fact.len() > CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES {
            return Err(format!(
                "connection::frame bundle fact has {} bytes, max {}",
                fact.len(),
                CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES
            ));
        }
        put_u32(&mut out, &mut offset, fact.len())?;
        put(&mut out, &mut offset, fact)?;
        offset += CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES - fact.len();
    }
    Ok(out)
}

struct DecodedInnerBundle {
    sender_endpoint_id: FactId,
    receiver_endpoint_id: FactId,
    facts: ConnectionFrameFactBundle,
}

fn decode_inner_bundle(size_class: u8, bytes: &[u8]) -> Result<DecodedInnerBundle, String> {
    match size_class {
        CONNECTION_FRAME_SIZE_CLASS_SMALL | CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE => {
            decode_packed_inner_bundle(bytes)
        }
        CONNECTION_FRAME_SIZE_CLASS_BUNDLE => decode_fixed_slot_inner_bundle(bytes),
        other => Err(format!(
            "unknown connection::frame frame size class {other}"
        )),
    }
}

fn decode_packed_inner_bundle(bytes: &[u8]) -> Result<DecodedInnerBundle, String> {
    let mut reader = Reader::new(bytes);
    if reader.take(4)? != INNER_BUNDLE_TAG {
        return Err("expected connection::frame inner bundle".to_string());
    }
    let version = reader.u8()?;
    if version != INNER_BUNDLE_VERSION {
        return Err(format!(
            "unsupported connection::frame inner bundle version {version}"
        ));
    }
    let sender_endpoint_id = reader.id32()?;
    let receiver_endpoint_id = reader.id32()?;
    let count = reader.u32()? as usize;
    if count == 0 {
        return Err("connection::frame inner bundle must contain at least one fact".to_string());
    }
    let mut facts = ConnectionFrameFactBundle::new();
    for _ in 0..count {
        facts.push(reader.bytes()?.to_vec());
    }
    reader.finish_zero_padding()?;
    Ok(DecodedInnerBundle {
        sender_endpoint_id,
        receiver_endpoint_id,
        facts,
    })
}

fn decode_fixed_slot_inner_bundle(bytes: &[u8]) -> Result<DecodedInnerBundle, String> {
    if bytes.len() != CONNECTION_FRAME_BUNDLE_PLAINTEXT_BYTES {
        return Err("connection::frame fixed-slot bundle length mismatch".to_string());
    }
    let mut reader = Reader::new(bytes);
    if reader.take(4)? != INNER_BUNDLE_TAG {
        return Err("expected connection::frame inner bundle".to_string());
    }
    let version = reader.u8()?;
    if version != INNER_BUNDLE_VERSION {
        return Err(format!(
            "unsupported connection::frame inner bundle version {version}"
        ));
    }
    let sender_endpoint_id = reader.id32()?;
    let receiver_endpoint_id = reader.id32()?;
    let count = reader.u32()? as usize;
    if count == 0 {
        return Err("connection::frame inner bundle must contain at least one fact".to_string());
    }
    if count > CONNECTION_FRAME_BUNDLE_FACT_SLOTS {
        return Err("connection::frame inner bundle count exceeds slot count".to_string());
    }

    let mut facts = ConnectionFrameFactBundle::new();
    for index in 0..CONNECTION_FRAME_BUNDLE_FACT_SLOTS {
        let len = reader.u32()? as usize;
        let slot = reader.take(CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES)?;
        if index < count {
            if len > CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES {
                return Err("connection::frame inner bundle slot length exceeds slot".to_string());
            }
            if slot[len..].iter().any(|byte| *byte != 0) {
                return Err("connection::frame inner bundle slot has nonzero padding".to_string());
            }
            facts.push(slot[..len].to_vec());
        } else if len != 0 || slot.iter().any(|byte| *byte != 0) {
            return Err("connection::frame unused bundle slot is nonzero".to_string());
        }
    }
    reader.finish()?;
    Ok(DecodedInnerBundle {
        sender_endpoint_id,
        receiver_endpoint_id,
        facts,
    })
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

    fn id32(&mut self) -> Result<FactId, String> {
        Ok(self.take(32)?.try_into().unwrap())
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| "connection::frame inner bundle length overflow".to_string())?;
        if end > self.bytes.len() {
            return Err("truncated connection::frame inner bundle".to_string());
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn finish_zero_padding(self) -> Result<(), String> {
        if self.bytes[self.offset..].iter().all(|byte| *byte == 0) {
            Ok(())
        } else {
            Err("connection::frame inner bundle has nonzero padding".to_string())
        }
    }

    fn finish(self) -> Result<(), String> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err("connection::frame inner bundle has trailing bytes".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Debug;

    fn id(byte: u8) -> Id32 {
        FixedBytes([byte; 32])
    }

    fn nonce(byte: u8) -> Nonce24 {
        FixedBytes([byte; XCHACHA20_POLY1305_NONCE_BYTES])
    }

    fn assert_frame_roundtrips_fixed_width<T>(frame: T, expected_len: usize)
    where
        T: FixedLayout + PartialEq + Debug,
    {
        let mut encoded = vec![0; T::LEN];

        frame.encode(&mut encoded).expect("encode frame");

        assert_eq!(encoded.len(), expected_len);
        assert_eq!(T::decode(&encoded).expect("decode frame"), frame);
    }

    #[test]
    fn connection_frame_roundtrips_fixed_width() {
        assert_frame_roundtrips_fixed_width(
            ConnectionFrameSmallV1 {
                connection_id: id(3),
                nonce: nonce(4),
                ciphertext: Ciphertext::<CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES>::new(&vec![
                    5;
                    CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES
                ])
                .expect("small ciphertext"),
            },
            CONNECTION_FRAME_SMALL_WIRE_BYTES,
        );

        assert_frame_roundtrips_fixed_width(
            ConnectionFrameBundleV1 {
                connection_id: id(3),
                nonce: nonce(4),
                ciphertext: Ciphertext::<CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES>::new(&vec![
                    6;
                    CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES
                ])
                .expect("bundle ciphertext"),
            },
            CONNECTION_FRAME_BUNDLE_WIRE_BYTES,
        );

        assert_frame_roundtrips_fixed_width(
            ConnectionFrameFileSliceV1 {
                connection_id: id(3),
                nonce: nonce(4),
                ciphertext: Ciphertext::<CONNECTION_FRAME_FILE_SLICE_CIPHERTEXT_BYTES>::new(
                    &vec![7; CONNECTION_FRAME_FILE_SLICE_CIPHERTEXT_BYTES],
                )
                .expect("file-slice ciphertext"),
            },
            CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES,
        );
    }
}
