//! Fixed wire layout for encrypted connection frames.
//!
//! Connection frames have two outer shapes, `ConnectionFrameSmallV1` and
//! `ConnectionFrameLargeV1`. Both share a public header containing tag,
//! version, size class, endpoint ids, connection id, and nonce; only the
//! encrypted payload slot capacity differs. Received-frame fact encoding also
//! stores normalized origin metadata around the raw frame bytes for ephemeral
//! projection.
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

use super::fact::{ConnectionFrameLargeFact, ConnectionFrameSmallFact};
use crate::protocol::connection::fact_receipt::create::normalize_origin_addr_bytes;

/// Ephemeral projection-input tag for one received small connection frame.
pub const TYPE_CONNECTION_FRAME_SMALL: u8 = 168;

/// Ephemeral projection-input tag for one received large connection frame.
pub const TYPE_CONNECTION_FRAME_LARGE: u8 = 169;

/// Public tag prefix shared by both connection::frame frame variants.
pub const CONNECTION_FRAME_TAG: Tag<4> = fixed_tag(b"TRNS");

/// Current connection::frame frame version.
pub const CONNECTION_FRAME_VERSION: u8 = 1;

/// Size class byte for [`ConnectionFrameSmallV1`].
pub const CONNECTION_FRAME_SIZE_CLASS_SMALL: u8 = 0;

/// Size class byte for [`ConnectionFrameLargeV1`].
pub const CONNECTION_FRAME_SIZE_CLASS_LARGE: u8 = 1;

/// Plaintext capacity of a small connection::frame frame (4 KiB).
///
/// Small frames carry control traffic and single events; the batcher chooses
/// this class when the packed inner bytes fit in the small budget.
pub const CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES: usize = 4 * 1024;

/// Plaintext capacity of a large connection::frame frame (1 MiB).
///
/// Large frames carry batched events. The batcher chooses this class for any
/// batch that exceeds the small plaintext budget. The architecture doc does
/// not pin exact numbers; these are the poc-10 defaults and may evolve.
pub const CONNECTION_FRAME_LARGE_PLAINTEXT_BYTES: usize = 1024 * 1024;

/// Ciphertext slot capacity for small frames (plaintext + AEAD tag).
pub const CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES: usize =
    CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;

/// Ciphertext slot capacity for large frames (plaintext + AEAD tag).
pub const CONNECTION_FRAME_LARGE_CIPHERTEXT_BYTES: usize =
    CONNECTION_FRAME_LARGE_PLAINTEXT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;

/// Fixed public header size (tag + version + size class + 3 ids + nonce).
pub const CONNECTION_FRAME_HEADER_BYTES: usize = Tag::<4>::LEN
    + wire::U8_BYTES
    + wire::U8_BYTES
    + Id32::LEN
    + Id32::LEN
    + Id32::LEN
    + Nonce24::LEN;

/// Outer wire length for a [`ConnectionFrameSmallV1`] frame.
pub const CONNECTION_FRAME_SMALL_WIRE_BYTES: usize =
    CONNECTION_FRAME_HEADER_BYTES + Ciphertext::<CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES>::LEN;

/// Outer wire length for a [`ConnectionFrameLargeV1`] frame.
pub const CONNECTION_FRAME_LARGE_WIRE_BYTES: usize =
    CONNECTION_FRAME_HEADER_BYTES + Ciphertext::<CONNECTION_FRAME_LARGE_CIPHERTEXT_BYTES>::LEN;

const VERSION_OFFSET: usize = Tag::<4>::LEN;
const SIZE_CLASS_OFFSET: usize = VERSION_OFFSET + wire::U8_BYTES;
const SENDER_OFFSET: usize = SIZE_CLASS_OFFSET + wire::U8_BYTES;
const RECEIVER_OFFSET: usize = SENDER_OFFSET + Id32::LEN;
const CONNECTION_OFFSET: usize = RECEIVER_OFFSET + Id32::LEN;
const NONCE_OFFSET: usize = CONNECTION_OFFSET + Id32::LEN;
const CIPHERTEXT_OFFSET: usize = NONCE_OFFSET + Nonce24::LEN;

pub fn encode_small_fact(fact: &ConnectionFrameSmallFact) -> Result<Vec<u8>, String> {
    encode_received_frame_fact(
        TYPE_CONNECTION_FRAME_SMALL,
        CONNECTION_FRAME_SIZE_CLASS_SMALL,
        &fact.origin_addr,
        fact.received_at_local_ms,
        &fact.frame,
    )
}

pub fn decode_small_fact(bytes: &[u8]) -> Result<ConnectionFrameSmallFact, String> {
    let (origin_addr, received_at_local_ms, frame) =
        decode_received_frame_fact(bytes, TYPE_CONNECTION_FRAME_SMALL)?;
    require_frame_size_class(&frame, CONNECTION_FRAME_SIZE_CLASS_SMALL)?;
    Ok(ConnectionFrameSmallFact {
        origin_addr,
        received_at_local_ms,
        frame,
    })
}

pub fn encode_large_fact(fact: &ConnectionFrameLargeFact) -> Result<Vec<u8>, String> {
    encode_received_frame_fact(
        TYPE_CONNECTION_FRAME_LARGE,
        CONNECTION_FRAME_SIZE_CLASS_LARGE,
        &fact.origin_addr,
        fact.received_at_local_ms,
        &fact.frame,
    )
}

pub fn decode_large_fact(bytes: &[u8]) -> Result<ConnectionFrameLargeFact, String> {
    let (origin_addr, received_at_local_ms, frame) =
        decode_received_frame_fact(bytes, TYPE_CONNECTION_FRAME_LARGE)?;
    require_frame_size_class(&frame, CONNECTION_FRAME_SIZE_CLASS_LARGE)?;
    Ok(ConnectionFrameLargeFact {
        origin_addr,
        received_at_local_ms,
        frame,
    })
}

fn encode_received_frame_fact(
    tag: u8,
    expected_size_class: u8,
    origin_addr: &[u8],
    received_at_local_ms: u64,
    frame: &[u8],
) -> Result<Vec<u8>, String> {
    require_frame_size_class(frame, expected_size_class)?;
    let origin_addr = normalize_origin_addr_bytes(origin_addr)?;
    let mut out = wire::Writer::with_capacity(1 + 4 + origin_addr.len() + 8 + 4 + frame.len());
    out.u8(tag);
    out.bytes_u32be(&origin_addr).map_err(wire_err)?;
    out.u64be(received_at_local_ms);
    out.bytes_u32be(frame).map_err(wire_err)?;
    Ok(out.finish())
}

fn decode_received_frame_fact(bytes: &[u8], tag: u8) -> Result<(Vec<u8>, u64, Vec<u8>), String> {
    let mut reader = wire::Reader::new(bytes);
    reader.expect_u8(tag).map_err(wire_err)?;
    let origin_addr = normalize_origin_addr_bytes(reader.bytes_u32be().map_err(wire_err)?)?;
    let received_at_local_ms = reader.u64be().map_err(wire_err)?;
    let frame = reader.bytes_u32be().map_err(wire_err)?.to_vec();
    reader.finish().map_err(wire_err)?;
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
    pub sender_endpoint_id: Id32,
    pub receiver_endpoint_id: Id32,
    pub connection_id: Id32,
    pub nonce: Nonce24,
    pub ciphertext: Ciphertext<CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES>,
}

/// Fixed-width large connection::frame frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFrameLargeV1 {
    pub sender_endpoint_id: Id32,
    pub receiver_endpoint_id: Id32,
    pub connection_id: Id32,
    pub nonce: Nonce24,
    pub ciphertext: Ciphertext<CONNECTION_FRAME_LARGE_CIPHERTEXT_BYTES>,
}

impl FixedLayout for ConnectionFrameSmallV1 {
    const LEN: usize = CONNECTION_FRAME_SMALL_WIRE_BYTES;

    fn encode(&self, out: &mut [u8]) -> Result<(), WireError> {
        encode_header(
            out,
            Self::LEN,
            CONNECTION_FRAME_SIZE_CLASS_SMALL,
            &self.sender_endpoint_id,
            &self.receiver_endpoint_id,
            &self.connection_id,
            &self.nonce,
        )?;
        self.ciphertext.encode(&mut out[CIPHERTEXT_OFFSET..])
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let (sender, receiver, connection, nonce) =
            decode_header(bytes, Self::LEN, CONNECTION_FRAME_SIZE_CLASS_SMALL)?;
        let ciphertext = Ciphertext::<CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES>::decode(
            &bytes[CIPHERTEXT_OFFSET..],
        )?;
        Ok(Self {
            sender_endpoint_id: sender,
            receiver_endpoint_id: receiver,
            connection_id: connection,
            nonce,
            ciphertext,
        })
    }
}

impl FixedLayout for ConnectionFrameLargeV1 {
    const LEN: usize = CONNECTION_FRAME_LARGE_WIRE_BYTES;

    fn encode(&self, out: &mut [u8]) -> Result<(), WireError> {
        encode_header(
            out,
            Self::LEN,
            CONNECTION_FRAME_SIZE_CLASS_LARGE,
            &self.sender_endpoint_id,
            &self.receiver_endpoint_id,
            &self.connection_id,
            &self.nonce,
        )?;
        self.ciphertext.encode(&mut out[CIPHERTEXT_OFFSET..])
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let (sender, receiver, connection, nonce) =
            decode_header(bytes, Self::LEN, CONNECTION_FRAME_SIZE_CLASS_LARGE)?;
        let ciphertext = Ciphertext::<CONNECTION_FRAME_LARGE_CIPHERTEXT_BYTES>::decode(
            &bytes[CIPHERTEXT_OFFSET..],
        )?;
        Ok(Self {
            sender_endpoint_id: sender,
            receiver_endpoint_id: receiver,
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
    pub sender_endpoint_id: Id32,
    pub receiver_endpoint_id: Id32,
    pub connection_id: Id32,
    pub nonce: Nonce24,
}

/// Borrowed connection::frame frame payload recovered without materializing a large
/// fixed-slot value on the stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFrameParts<'a> {
    pub header: ConnectionFrameHeader,
    pub ciphertext: &'a [u8],
}

/// Inspect just the public header of a connection::frame frame.
///
/// Returns the size class byte and addressing fields. The caller decides which
/// of [`ConnectionFrameSmallV1::decode`] or [`ConnectionFrameLargeV1::decode`] to run based on
/// `size_class` and the outer length.
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
    let size_class = wire::take_u8(&bytes[SIZE_CLASS_OFFSET..SENDER_OFFSET])?;
    let sender_endpoint_id = Id32::decode(&bytes[SENDER_OFFSET..RECEIVER_OFFSET])?;
    let receiver_endpoint_id = Id32::decode(&bytes[RECEIVER_OFFSET..CONNECTION_OFFSET])?;
    let connection_id = Id32::decode(&bytes[CONNECTION_OFFSET..NONCE_OFFSET])?;
    let nonce = Nonce24::decode(&bytes[NONCE_OFFSET..CIPHERTEXT_OFFSET])?;
    Ok(ConnectionFrameHeader {
        size_class,
        sender_endpoint_id,
        receiver_endpoint_id,
        connection_id,
        nonce,
    })
}

/// Decode the public header and borrowed ciphertext slot for either size
/// class without copying the full padded payload.
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

/// Encode a connection::frame frame for either size class from already-encrypted bytes.
pub fn encode_frame_bytes(
    size_class: u8,
    sender_endpoint_id: Id32,
    receiver_endpoint_id: Id32,
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
    encode_header(
        &mut out,
        wire_len,
        size_class,
        &sender_endpoint_id,
        &receiver_endpoint_id,
        &connection_id,
        &nonce,
    )?;
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
    sender: &Id32,
    receiver: &Id32,
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
    wire::put_u8(size_class, &mut out[SIZE_CLASS_OFFSET..SENDER_OFFSET])?;
    sender.encode(&mut out[SENDER_OFFSET..RECEIVER_OFFSET])?;
    receiver.encode(&mut out[RECEIVER_OFFSET..CONNECTION_OFFSET])?;
    connection.encode(&mut out[CONNECTION_OFFSET..NONCE_OFFSET])?;
    nonce.encode(&mut out[NONCE_OFFSET..CIPHERTEXT_OFFSET])?;
    Ok(())
}

fn decode_header(
    bytes: &[u8],
    expected_len: usize,
    expected_size_class: u8,
) -> Result<(Id32, Id32, Id32, Nonce24), WireError> {
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
    let size_class = wire::take_u8(&bytes[SIZE_CLASS_OFFSET..SENDER_OFFSET])?;
    if size_class != expected_size_class {
        return Err(WireError::InvalidBool { actual: size_class });
    }
    let sender = Id32::decode(&bytes[SENDER_OFFSET..RECEIVER_OFFSET])?;
    let receiver = Id32::decode(&bytes[RECEIVER_OFFSET..CONNECTION_OFFSET])?;
    let connection = Id32::decode(&bytes[CONNECTION_OFFSET..NONCE_OFFSET])?;
    let nonce = Nonce24::decode(&bytes[NONCE_OFFSET..CIPHERTEXT_OFFSET])?;
    Ok((sender, receiver, connection, nonce))
}

fn frame_shape(size_class: u8) -> Result<(usize, usize), WireError> {
    match size_class {
        CONNECTION_FRAME_SIZE_CLASS_SMALL => Ok((
            CONNECTION_FRAME_SMALL_WIRE_BYTES,
            CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES,
        )),
        CONNECTION_FRAME_SIZE_CLASS_LARGE => Ok((
            CONNECTION_FRAME_LARGE_WIRE_BYTES,
            CONNECTION_FRAME_LARGE_CIPHERTEXT_BYTES,
        )),
        other => Err(WireError::InvalidBool { actual: other }),
    }
}

/// Sanity-check assertion that the constants above stay consistent.
const _: () = {
    assert!(
        CONNECTION_FRAME_HEADER_BYTES == 4 + 1 + 1 + 32 + 32 + 32 + XCHACHA20_POLY1305_NONCE_BYTES
    );
    assert!(CONNECTION_FRAME_SMALL_WIRE_BYTES < CONNECTION_FRAME_LARGE_WIRE_BYTES);
};

// ---------------------------------------------------------------------------
// Connection-frame sealing and inner bundle helpers.
// ---------------------------------------------------------------------------

const FRAME_PURPOSE: &[u8] = b"topo connection::frame frame v1";
const INNER_BUNDLE_TAG: &[u8; 4] = b"TIB1";
const INNER_BUNDLE_VERSION: u8 = 1;
const INNER_BUNDLE_HEADER_BYTES: usize = 4 + 1 + 4;
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

pub fn connection_send_nonce(connection_id: FactId, fact_ids: &[FactId]) -> XChaCha20Poly1305Nonce {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:connection::frame-connection-send-nonce:v1:");
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
    Ok(decode_frame_parts(frame)
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
    encode_frame_bytes(
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
    facts: ConnectionFrameFactBundle,
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
            "connection::frame frame plaintext must fill fixed slot: expected {} got {}",
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
    if len <= CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES {
        Ok(CONNECTION_FRAME_SIZE_CLASS_SMALL)
    } else if len <= CONNECTION_FRAME_LARGE_PLAINTEXT_BYTES {
        Ok(CONNECTION_FRAME_SIZE_CLASS_LARGE)
    } else {
        Err(format!(
            "connection::frame inner payload too large: max {} got {len}",
            CONNECTION_FRAME_LARGE_PLAINTEXT_BYTES
        ))
    }
}

fn plaintext_len_for_size_class(size_class: u8) -> Result<usize, String> {
    match size_class {
        CONNECTION_FRAME_SIZE_CLASS_SMALL => Ok(CONNECTION_FRAME_SMALL_PLAINTEXT_BYTES),
        CONNECTION_FRAME_SIZE_CLASS_LARGE => Ok(CONNECTION_FRAME_LARGE_PLAINTEXT_BYTES),
        other => Err(format!(
            "unknown connection::frame frame size class {other}"
        )),
    }
}

fn ciphertext_len_for_size_class(size_class: u8) -> Result<usize, String> {
    match size_class {
        CONNECTION_FRAME_SIZE_CLASS_SMALL => Ok(CONNECTION_FRAME_SMALL_CIPHERTEXT_BYTES),
        CONNECTION_FRAME_SIZE_CLASS_LARGE => Ok(CONNECTION_FRAME_LARGE_CIPHERTEXT_BYTES),
        other => Err(format!(
            "unknown connection::frame frame size class {other}"
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
    facts: &ConnectionFrameFactBundle,
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
    put_u32(&mut out, &mut offset, facts.len())?;
    for fact in facts.iter() {
        put_u32(&mut out, &mut offset, fact.len())?;
        put(&mut out, &mut offset, fact)?;
    }
    Ok(out)
}

fn decode_inner_bundle(bytes: &[u8]) -> Result<ConnectionFrameFactBundle, String> {
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
    let count = reader.u32()? as usize;
    if count == 0 {
        return Err("connection::frame inner bundle must contain at least one fact".to_string());
    }
    let mut facts = ConnectionFrameFactBundle::new();
    for _ in 0..count {
        facts.push(reader.bytes()?.to_vec());
    }
    reader.finish_zero_padding()?;
    Ok(facts)
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
}
