//! Canonical byte encoding for bundle connection-frame wire facts.
//!
//! This file owns byte construction only: the fact tag, the fixed fact width,
//! and the wire encoding of one bundle encrypted connection frame. It does not
//! decode, authenticate, inspect context, or materialize rows.

use crate::core::crypto::{
    XChaCha20Poly1305Nonce, XCHACHA20_POLY1305_NONCE_BYTES, XCHACHA20_POLY1305_TAG_BYTES,
};
use crate::core::facts::FactId;
use crate::core::wire::{self, fixed_tag, Ciphertext, FixedLayout, Id32, Nonce24, Tag, WireError};
use crate::protocol::content::file;

use super::fact::ConnectionFrameBundleFact;

pub const TYPE_CONNECTION_FRAME_BUNDLE: u8 = 170;

/// Public tag prefix for bundle connection frames.
pub const CONNECTION_FRAME_TAG: Tag<4> = fixed_tag(b"TRNS");

/// Current established-frame wire version.
pub const CONNECTION_FRAME_VERSION: u8 = 1;

/// Size class byte for bundle frames.
pub const CONNECTION_FRAME_SIZE_CLASS_BUNDLE: u8 = 2;

/// Maximum fact bytes carried in one padded bundle slot.
pub const CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES: usize = file::encode::CONTENT_FILE_BYTES;

/// Number of padded fact slots in one bundle frame.
pub const CONNECTION_FRAME_BUNDLE_FACT_SLOTS: usize = (64 * 1024 - INNER_BUNDLE_HEADER_BYTES)
    / (INNER_FACT_LEN_BYTES + CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES);

/// Plaintext capacity of a bundle connection frame.
pub const CONNECTION_FRAME_BUNDLE_PLAINTEXT_BYTES: usize = INNER_BUNDLE_HEADER_BYTES
    + CONNECTION_FRAME_BUNDLE_FACT_SLOTS
        * (INNER_FACT_LEN_BYTES + CONNECTION_FRAME_BUNDLE_FACT_SLOT_BYTES);

/// Ciphertext slot capacity for bundle frames (plaintext + AEAD tag).
pub const CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES: usize =
    CONNECTION_FRAME_BUNDLE_PLAINTEXT_BYTES + XCHACHA20_POLY1305_TAG_BYTES;

/// Fixed public header size (tag + version + size class + connection id + nonce).
pub const CONNECTION_FRAME_HEADER_BYTES: usize =
    Tag::<4>::LEN + wire::U8_BYTES + wire::U8_BYTES + Id32::LEN + Nonce24::LEN;

/// Outer wire length for a bundle connection frame.
pub const CONNECTION_FRAME_BUNDLE_WIRE_BYTES: usize =
    CONNECTION_FRAME_HEADER_BYTES + Ciphertext::<CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES>::LEN;

const VERSION_OFFSET: usize = Tag::<4>::LEN;
const SIZE_CLASS_OFFSET: usize = VERSION_OFFSET + wire::U8_BYTES;
const CONNECTION_OFFSET: usize = SIZE_CLASS_OFFSET + wire::U8_BYTES;
const NONCE_OFFSET: usize = CONNECTION_OFFSET + Id32::LEN;
pub(crate) const CIPHERTEXT_OFFSET: usize = NONCE_OFFSET + Nonce24::LEN;

pub const CONNECTION_FRAME_BUNDLE_FACT_BYTES: usize =
    1 + wire::FixedSlot::<CONNECTION_FRAME_BUNDLE_WIRE_BYTES>::LEN;

const FRAME_PURPOSE: &[u8] = b"topo connection::frame frame v1";
const INNER_BUNDLE_HEADER_BYTES: usize = 4 + 1 + 32 + 32 + 4;
const INNER_FACT_LEN_BYTES: usize = 4;

/// Fixed-width bundle connection frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFrameBundleV1 {
    pub connection_id: Id32,
    pub nonce: Nonce24,
    pub ciphertext: Ciphertext<CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES>,
}

impl FixedLayout for ConnectionFrameBundleV1 {
    const LEN: usize = CONNECTION_FRAME_BUNDLE_WIRE_BYTES;

    fn encode(&self, out: &mut [u8]) -> Result<(), WireError> {
        encode_header(out, Self::LEN, &self.connection_id, &self.nonce)?;
        self.ciphertext.encode(&mut out[CIPHERTEXT_OFFSET..])
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let (connection_id, nonce) = decode_header(bytes, Self::LEN)?;
        let ciphertext = Ciphertext::<CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES>::decode(
            &bytes[CIPHERTEXT_OFFSET..],
        )?;
        Ok(Self {
            connection_id,
            nonce,
            ciphertext,
        })
    }
}

pub fn encode_fact(fact: &ConnectionFrameBundleFact) -> Result<Vec<u8>, String> {
    if fact.frame.len() != CONNECTION_FRAME_BUNDLE_WIRE_BYTES {
        return Err(format!(
            "connection frame bundle bytes must be {} bytes",
            CONNECTION_FRAME_BUNDLE_WIRE_BYTES
        ));
    }
    ConnectionFrameBundleV1::decode(fact.frame.bytes()).map_err(wire_err)?;
    let mut out = wire::Writer::with_capacity(CONNECTION_FRAME_BUNDLE_FACT_BYTES);
    out.u8(TYPE_CONNECTION_FRAME_BUNDLE);
    out.fixed_slot_value(&fact.frame).map_err(wire_err)?;
    out.finish_exact(CONNECTION_FRAME_BUNDLE_FACT_BYTES)
        .map_err(wire_err)
}

/// Encode a bundle connection frame from already-encrypted bytes.
pub fn encode_frame_bytes(
    connection_id: Id32,
    nonce: Nonce24,
    ciphertext: &[u8],
) -> Result<Vec<u8>, WireError> {
    if ciphertext.len() > CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES {
        return Err(WireError::ValueTooLarge {
            max: CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES,
            actual: ciphertext.len(),
        });
    }
    let mut out = vec![0; CONNECTION_FRAME_BUNDLE_WIRE_BYTES];
    encode_header(
        &mut out,
        CONNECTION_FRAME_BUNDLE_WIRE_BYTES,
        &connection_id,
        &nonce,
    )?;
    wire::put_u32be(
        ciphertext.len() as u32,
        &mut out[CIPHERTEXT_OFFSET..CIPHERTEXT_OFFSET + wire::U32_BYTES],
    )?;
    out[CIPHERTEXT_OFFSET + wire::U32_BYTES
        ..CIPHERTEXT_OFFSET + wire::U32_BYTES + ciphertext.len()]
        .copy_from_slice(ciphertext);
    Ok(out)
}

pub(crate) fn frame_associated_data(
    connection_id: FactId,
    nonce: XChaCha20Poly1305Nonce,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAME_PURPOSE.len() + 1 + 32 + 24);
    out.extend_from_slice(FRAME_PURPOSE);
    out.push(CONNECTION_FRAME_SIZE_CLASS_BUNDLE);
    out.extend_from_slice(&connection_id);
    out.extend_from_slice(&nonce);
    out
}

fn encode_header(
    out: &mut [u8],
    expected_len: usize,
    connection_id: &Id32,
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
    wire::put_u8(
        CONNECTION_FRAME_SIZE_CLASS_BUNDLE,
        &mut out[SIZE_CLASS_OFFSET..CONNECTION_OFFSET],
    )?;
    connection_id.encode(&mut out[CONNECTION_OFFSET..NONCE_OFFSET])?;
    nonce.encode(&mut out[NONCE_OFFSET..CIPHERTEXT_OFFSET])?;
    Ok(())
}

fn decode_header(bytes: &[u8], expected_len: usize) -> Result<(Id32, Nonce24), WireError> {
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
    if size_class != CONNECTION_FRAME_SIZE_CLASS_BUNDLE {
        return Err(WireError::InvalidBool { actual: size_class });
    }
    let connection_id = Id32::decode(&bytes[CONNECTION_OFFSET..NONCE_OFFSET])?;
    let nonce = Nonce24::decode(&bytes[NONCE_OFFSET..CIPHERTEXT_OFFSET])?;
    Ok((connection_id, nonce))
}

pub(crate) fn wire_err(err: WireError) -> String {
    format!("{err:?}")
}

const _: () = {
    assert!(CONNECTION_FRAME_HEADER_BYTES == 4 + 1 + 1 + 32 + XCHACHA20_POLY1305_NONCE_BYTES);
};
