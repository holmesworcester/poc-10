//! Fixed-width wire layouts for poc-10 transport::transit frames.
//!
//! Transit publishes exactly two outer frame shapes — `TransitSmallV1` and
//! `TransitLargeV1` — that share a fixed public header and differ only in the
//! size of their encrypted payload slot. The outer wire length reveals only
//! the size class; per-batch sizing is hidden inside the ciphertext.

use crate::core::crypto::{XCHACHA20_POLY1305_NONCE_BYTES, XCHACHA20_POLY1305_TAG_BYTES};
use crate::core::wire::{self, fixed_tag, Ciphertext, FixedLayout, Id32, Nonce24, Tag, WireError};

/// Public tag prefix shared by both transport::transit frame variants.
pub const TRANSIT_FRAME_TAG: Tag<4> = fixed_tag(b"TRNS");

/// Current transport::transit frame version.
pub const TRANSIT_FRAME_VERSION: u8 = 1;

/// Size class byte for [`TransitSmallV1`].
pub const TRANSIT_FRAME_SIZE_CLASS_SMALL: u8 = 0;

/// Size class byte for [`TransitLargeV1`].
pub const TRANSIT_FRAME_SIZE_CLASS_LARGE: u8 = 1;

/// Plaintext capacity of a small transport::transit frame (4 KiB).
///
/// Small frames carry control traffic and single events; the batcher chooses
/// this class when the packed inner bytes fit in the small budget.
pub const TRANSIT_SMALL_PLAINTEXT_BYTES: usize = 4 * 1024;

/// Plaintext capacity of a large transport::transit frame (1 MiB).
///
/// Large frames carry batched events. The batcher chooses this class for any
/// batch that exceeds the small plaintext budget. The architecture doc does
/// not pin exact numbers; these are the poc-10 defaults and may evolve.
pub const TRANSIT_LARGE_PLAINTEXT_BYTES: usize = 1024 * 1024;

/// Ciphertext slot capacity for small frames (plaintext + AEAD tag).
pub const TRANSIT_SMALL_CIPHERTEXT_BYTES: usize =
    TRANSIT_SMALL_PLAINTEXT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;

/// Ciphertext slot capacity for large frames (plaintext + AEAD tag).
pub const TRANSIT_LARGE_CIPHERTEXT_BYTES: usize =
    TRANSIT_LARGE_PLAINTEXT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;

/// Fixed public header size (tag + version + size class + 3 ids + nonce).
pub const TRANSIT_HEADER_BYTES: usize = Tag::<4>::LEN
    + wire::U8_BYTES
    + wire::U8_BYTES
    + Id32::LEN
    + Id32::LEN
    + Id32::LEN
    + Nonce24::LEN;

/// Outer wire length for a [`TransitSmallV1`] frame.
pub const TRANSIT_SMALL_WIRE_BYTES: usize =
    TRANSIT_HEADER_BYTES + Ciphertext::<TRANSIT_SMALL_CIPHERTEXT_BYTES>::LEN;

/// Outer wire length for a [`TransitLargeV1`] frame.
pub const TRANSIT_LARGE_WIRE_BYTES: usize =
    TRANSIT_HEADER_BYTES + Ciphertext::<TRANSIT_LARGE_CIPHERTEXT_BYTES>::LEN;

const VERSION_OFFSET: usize = Tag::<4>::LEN;
const SIZE_CLASS_OFFSET: usize = VERSION_OFFSET + wire::U8_BYTES;
const SENDER_OFFSET: usize = SIZE_CLASS_OFFSET + wire::U8_BYTES;
const RECEIVER_OFFSET: usize = SENDER_OFFSET + Id32::LEN;
const CONNECTION_OFFSET: usize = RECEIVER_OFFSET + Id32::LEN;
const NONCE_OFFSET: usize = CONNECTION_OFFSET + Id32::LEN;
const CIPHERTEXT_OFFSET: usize = NONCE_OFFSET + Nonce24::LEN;

/// Fixed-width small transport::transit frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitSmallV1 {
    pub sender_endpoint_id: Id32,
    pub receiver_endpoint_id: Id32,
    pub connection_id: Id32,
    pub nonce: Nonce24,
    pub ciphertext: Ciphertext<TRANSIT_SMALL_CIPHERTEXT_BYTES>,
}

/// Fixed-width large transport::transit frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitLargeV1 {
    pub sender_endpoint_id: Id32,
    pub receiver_endpoint_id: Id32,
    pub connection_id: Id32,
    pub nonce: Nonce24,
    pub ciphertext: Ciphertext<TRANSIT_LARGE_CIPHERTEXT_BYTES>,
}

impl FixedLayout for TransitSmallV1 {
    const LEN: usize = TRANSIT_SMALL_WIRE_BYTES;

    fn encode(&self, out: &mut [u8]) -> Result<(), WireError> {
        encode_header(
            out,
            Self::LEN,
            TRANSIT_FRAME_SIZE_CLASS_SMALL,
            &self.sender_endpoint_id,
            &self.receiver_endpoint_id,
            &self.connection_id,
            &self.nonce,
        )?;
        self.ciphertext.encode(&mut out[CIPHERTEXT_OFFSET..])
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let (sender, receiver, connection, nonce) =
            decode_header(bytes, Self::LEN, TRANSIT_FRAME_SIZE_CLASS_SMALL)?;
        let ciphertext =
            Ciphertext::<TRANSIT_SMALL_CIPHERTEXT_BYTES>::decode(&bytes[CIPHERTEXT_OFFSET..])?;
        Ok(Self {
            sender_endpoint_id: sender,
            receiver_endpoint_id: receiver,
            connection_id: connection,
            nonce,
            ciphertext,
        })
    }
}

impl FixedLayout for TransitLargeV1 {
    const LEN: usize = TRANSIT_LARGE_WIRE_BYTES;

    fn encode(&self, out: &mut [u8]) -> Result<(), WireError> {
        encode_header(
            out,
            Self::LEN,
            TRANSIT_FRAME_SIZE_CLASS_LARGE,
            &self.sender_endpoint_id,
            &self.receiver_endpoint_id,
            &self.connection_id,
            &self.nonce,
        )?;
        self.ciphertext.encode(&mut out[CIPHERTEXT_OFFSET..])
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let (sender, receiver, connection, nonce) =
            decode_header(bytes, Self::LEN, TRANSIT_FRAME_SIZE_CLASS_LARGE)?;
        let ciphertext =
            Ciphertext::<TRANSIT_LARGE_CIPHERTEXT_BYTES>::decode(&bytes[CIPHERTEXT_OFFSET..])?;
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
pub struct TransitFrameHeader {
    pub size_class: u8,
    pub sender_endpoint_id: Id32,
    pub receiver_endpoint_id: Id32,
    pub connection_id: Id32,
    pub nonce: Nonce24,
}

/// Borrowed transport::transit frame payload recovered without materializing a large
/// fixed-slot value on the stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitFrameParts<'a> {
    pub header: TransitFrameHeader,
    pub ciphertext: &'a [u8],
}

/// Inspect just the public header of a transport::transit frame.
///
/// Returns the size class byte and addressing fields. The caller decides which
/// of [`TransitSmallV1::decode`] or [`TransitLargeV1::decode`] to run based on
/// `size_class` and the outer length.
pub fn peek_frame_header(bytes: &[u8]) -> Result<TransitFrameHeader, WireError> {
    if bytes.len() < TRANSIT_HEADER_BYTES {
        return Err(WireError::WrongLength {
            expected: TRANSIT_HEADER_BYTES,
            actual: bytes.len(),
        });
    }
    let tag = Tag::<4>::decode(&bytes[..VERSION_OFFSET])?;
    if tag != TRANSIT_FRAME_TAG {
        return Err(WireError::NonZeroPadding { index: 0 });
    }
    let version = wire::take_u8(&bytes[VERSION_OFFSET..SIZE_CLASS_OFFSET])?;
    if version != TRANSIT_FRAME_VERSION {
        return Err(WireError::InvalidBool { actual: version });
    }
    let size_class = wire::take_u8(&bytes[SIZE_CLASS_OFFSET..SENDER_OFFSET])?;
    let sender_endpoint_id = Id32::decode(&bytes[SENDER_OFFSET..RECEIVER_OFFSET])?;
    let receiver_endpoint_id = Id32::decode(&bytes[RECEIVER_OFFSET..CONNECTION_OFFSET])?;
    let connection_id = Id32::decode(&bytes[CONNECTION_OFFSET..NONCE_OFFSET])?;
    let nonce = Nonce24::decode(&bytes[NONCE_OFFSET..CIPHERTEXT_OFFSET])?;
    Ok(TransitFrameHeader {
        size_class,
        sender_endpoint_id,
        receiver_endpoint_id,
        connection_id,
        nonce,
    })
}

/// Decode the public header and borrowed ciphertext slot for either size
/// class without copying the full padded payload.
pub fn decode_frame_parts(bytes: &[u8]) -> Result<TransitFrameParts<'_>, WireError> {
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
    Ok(TransitFrameParts {
        header,
        ciphertext: &slot[4..4 + ciphertext_len],
    })
}

/// Encode a transport::transit frame for either size class from already-encrypted bytes.
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
    TRANSIT_FRAME_TAG.encode(&mut out[..VERSION_OFFSET])?;
    wire::put_u8(
        TRANSIT_FRAME_VERSION,
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
    if tag != TRANSIT_FRAME_TAG {
        return Err(WireError::NonZeroPadding { index: 0 });
    }
    let version = wire::take_u8(&bytes[VERSION_OFFSET..SIZE_CLASS_OFFSET])?;
    if version != TRANSIT_FRAME_VERSION {
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
        TRANSIT_FRAME_SIZE_CLASS_SMALL => {
            Ok((TRANSIT_SMALL_WIRE_BYTES, TRANSIT_SMALL_CIPHERTEXT_BYTES))
        }
        TRANSIT_FRAME_SIZE_CLASS_LARGE => {
            Ok((TRANSIT_LARGE_WIRE_BYTES, TRANSIT_LARGE_CIPHERTEXT_BYTES))
        }
        other => Err(WireError::InvalidBool { actual: other }),
    }
}

/// Sanity-check assertion that the constants above stay consistent.
const _: () = {
    assert!(TRANSIT_HEADER_BYTES == 4 + 1 + 1 + 32 + 32 + 32 + XCHACHA20_POLY1305_NONCE_BYTES);
    assert!(TRANSIT_SMALL_WIRE_BYTES < TRANSIT_LARGE_WIRE_BYTES);
};
