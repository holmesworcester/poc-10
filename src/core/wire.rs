//! Fixed-layout wire primitives.
//!
//! This module owns the small, protocol-neutral byte codecs used by fact,
//! intent, and connection-frame layouts. It provides exact-length fixed byte arrays,
//! big-endian integers, one-byte booleans, zero-padded bounded slots, and simple
//! sequential readers and writers for assembling those pieces.
//!
//! `wire` guarantees mechanical encoding invariants only:
//!
//! - decoders and encoders operate on the exact byte lengths declared by their
//!   layout type;
//! - integer byte order is stable and big-endian;
//! - one-byte booleans accept only `0` and `1`;
//! - `FixedSlot` stores an explicit length and rejects non-zero padding after
//!   the logical payload;
//! - `Reader::finish` rejects trailing bytes when a caller asks for complete
//!   consumption.
//!
//! This module deliberately does not know protocol tags, fact kinds, table
//! schemas, context roles, signer authority, cryptographic validity, or semantic
//! ranges such as "this timestamp is plausible" or "this id is non-empty".
//! Owning fact and intent modules must layer those checks on top of these
//! primitives after decoding.
//!
//! Use this file when a layout needs a reusable mechanical primitive: exact
//! fixed bytes, bounded padded strings, big-endian counters, or sequential
//! reader/writer plumbing. Do not add protocol payload structs here. A protocol
//! fact or intent module should own its type, tag, validation, and test vectors,
//! while calling these helpers for the byte-level work.

use std::fmt;
use std::ops::{Deref, Range};

/// Errors reported by mechanical wire codecs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// A fixed-width layout or complete reader saw the wrong byte count.
    WrongLength { expected: usize, actual: usize },
    /// A bounded value did not fit in its declared slot or length prefix.
    ValueTooLarge { max: usize, actual: usize },
    /// A one-byte boolean contained neither `0` nor `1`.
    InvalidBool { actual: u8 },
    /// A tag or marker byte was not the expected value.
    UnexpectedU8 { expected: u8, actual: u8 },
    /// A decoded string was not valid UTF-8.
    InvalidUtf8,
    /// A zero-padded fixed text value contained a NUL before the padding tail.
    InteriorNul { index: usize },
    /// A bounded padded slot had non-zero bytes after its logical length.
    NonZeroPadding { index: usize },
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongLength { expected, actual } => {
                write!(formatter, "expected {expected} bytes, got {actual}")
            }
            Self::ValueTooLarge { max, actual } => {
                write!(formatter, "value has {actual} bytes, max {max}")
            }
            Self::InvalidBool { actual } => write!(formatter, "invalid bool byte {actual}"),
            Self::UnexpectedU8 { expected, actual } => {
                write!(formatter, "expected byte {expected}, got {actual}")
            }
            Self::InvalidUtf8 => write!(formatter, "invalid utf-8"),
            Self::InteriorNul { index } => write!(formatter, "interior NUL at {index}"),
            Self::NonZeroPadding { index } => write!(formatter, "non-zero padding at {index}"),
        }
    }
}

impl std::error::Error for WireError {}

/// Fixed-width encoding contract for layouts with a known byte length.
pub trait FixedLayout: Sized {
    /// Exact encoded byte length.
    const LEN: usize;

    /// Encode into an exact-size output buffer.
    fn encode(&self, out: &mut [u8]) -> Result<(), WireError>;
    /// Decode from an exact-size input buffer.
    fn decode(bytes: &[u8]) -> Result<Self, WireError>;
}

/// Fixed-size byte array used for ids, nonces, and tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FixedBytes<const N: usize>(pub [u8; N]);

impl<const N: usize> FixedLayout for FixedBytes<N> {
    const LEN: usize = N;

    fn encode(&self, out: &mut [u8]) -> Result<(), WireError> {
        expect_len(out, N)?;
        out.copy_from_slice(&self.0);
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        expect_len(bytes, N)?;
        let mut out = [0; N];
        out.copy_from_slice(bytes);
        Ok(Self(out))
    }
}

pub type Tag<const N: usize> = FixedBytes<N>;
pub type Id32 = FixedBytes<32>;
pub type Nonce24 = FixedBytes<24>;

pub const U8_BYTES: usize = 1;
pub const U16_BYTES: usize = 2;
pub const U32_BYTES: usize = 4;
pub const U64_BYTES: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FixedSlot<const N: usize> {
    len: usize,
    bytes: Box<[u8; N]>,
}

pub type Ciphertext<const N: usize> = FixedSlot<N>;

impl<const N: usize> FixedSlot<N> {
    pub const DATA_LEN: usize = N;

    /// Build a padded slot from logical bytes.
    pub fn new(bytes: &[u8]) -> Result<Self, WireError> {
        if bytes.len() > N {
            return Err(WireError::ValueTooLarge {
                max: N,
                actual: bytes.len(),
            });
        }

        let mut padded = boxed_zeroed_array::<N>();
        padded[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            len: bytes.len(),
            bytes: padded,
        })
    }

    /// Build a slot from already padded bytes and validate the padding.
    pub fn from_padded(len: usize, bytes: [u8; N]) -> Result<Self, WireError> {
        if len > N {
            return Err(WireError::ValueTooLarge {
                max: N,
                actual: len,
            });
        }

        validate_zero_padding(&bytes, len)?;
        Ok(Self {
            len,
            bytes: Box::new(bytes),
        })
    }

    /// Return the logical byte length.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Return whether the logical payload is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Return the logical payload bytes without padding.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes.as_ref()[..self.len]
    }

    /// Alias for callers that naturally treat the logical payload as a slice.
    pub fn as_slice(&self) -> &[u8] {
        self.bytes()
    }

    /// Return the full fixed-width padded slot.
    pub fn padded_bytes(&self) -> &[u8; N] {
        self.bytes.as_ref()
    }
}

impl<const N: usize> TryFrom<&[u8]> for FixedSlot<N> {
    type Error = WireError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::new(bytes)
    }
}

impl<const N: usize> AsRef<[u8]> for FixedSlot<N> {
    fn as_ref(&self) -> &[u8] {
        self.bytes()
    }
}

impl<const N: usize> Deref for FixedSlot<N> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.bytes()
    }
}

impl<const N: usize> FixedLayout for FixedSlot<N> {
    const LEN: usize = U32_BYTES + N;

    fn encode(&self, out: &mut [u8]) -> Result<(), WireError> {
        expect_len(out, Self::LEN)?;
        let len = u32::try_from(self.len).map_err(|_| WireError::ValueTooLarge {
            max: u32::MAX as usize,
            actual: self.len,
        })?;
        put_u32be(len, &mut out[..U32_BYTES])?;
        out[U32_BYTES..].fill(0);
        out[U32_BYTES..U32_BYTES + self.len].copy_from_slice(self.bytes());
        Ok(())
    }

    fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        expect_len(bytes, Self::LEN)?;
        let len = take_u32be(&bytes[..U32_BYTES])? as usize;
        if len > N {
            return Err(WireError::ValueTooLarge {
                max: N,
                actual: len,
            });
        }

        let mut padded = boxed_zeroed_array::<N>();
        padded.copy_from_slice(&bytes[U32_BYTES..]);
        validate_zero_padding(padded.as_ref(), len)?;
        Ok(Self { len, bytes: padded })
    }
}

/// Fixed-width UTF-8 text stored as bytes followed by zero padding.
///
/// The encoded form has no length prefix; the first zero byte starts padding.
/// Values with embedded NUL bytes are rejected so there is exactly one
/// canonical padded representation for each string.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FixedText<const N: usize> {
    len: usize,
    bytes: [u8; N],
}

impl<const N: usize> FixedText<N> {
    /// Build fixed text from a UTF-8 string.
    pub fn new(value: &str) -> Result<Self, WireError> {
        if let Some(index) = value.as_bytes().iter().position(|byte| *byte == 0) {
            return Err(WireError::InteriorNul { index });
        }
        if value.len() > N {
            return Err(WireError::ValueTooLarge {
                max: N,
                actual: value.len(),
            });
        }

        let mut bytes = [0; N];
        bytes[..value.len()].copy_from_slice(value.as_bytes());
        Ok(Self {
            len: value.len(),
            bytes,
        })
    }

    /// Build fixed text from its canonical padded bytes.
    pub fn from_padded(bytes: [u8; N]) -> Result<Self, WireError> {
        let len = bytes.iter().position(|byte| *byte == 0).unwrap_or(N);
        validate_zero_padding(&bytes, len)?;
        std::str::from_utf8(&bytes[..len]).map_err(|_| WireError::InvalidUtf8)?;
        Ok(Self { len, bytes })
    }

    /// Return the decoded UTF-8 string.
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len])
            .expect("FixedText validates UTF-8 at construction")
    }

    /// Return the logical UTF-8 bytes without padding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Return the canonical padded fixed-width bytes.
    pub fn padded_bytes(&self) -> &[u8; N] {
        &self.bytes
    }
}

impl<const N: usize> TryFrom<&str> for FixedText<N> {
    type Error = WireError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<const N: usize> AsRef<str> for FixedText<N> {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl<const N: usize> fmt::Display for FixedText<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl<const N: usize> PartialEq<&str> for FixedText<N> {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == *other
    }
}

impl<const N: usize> PartialEq<FixedText<N>> for &str {
    fn eq(&self, other: &FixedText<N>) -> bool {
        *self == other.as_str()
    }
}

impl<const N: usize> PartialEq<Vec<u8>> for FixedSlot<N> {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.bytes() == other.as_slice()
    }
}

impl<const N: usize> PartialEq<FixedSlot<N>> for Vec<u8> {
    fn eq(&self, other: &FixedSlot<N>) -> bool {
        self.as_slice() == other.bytes()
    }
}

impl<const N: usize> PartialEq<&[u8]> for FixedSlot<N> {
    fn eq(&self, other: &&[u8]) -> bool {
        self.bytes() == *other
    }
}

impl<const N: usize> PartialEq<FixedSlot<N>> for &[u8] {
    fn eq(&self, other: &FixedSlot<N>) -> bool {
        *self == other.bytes()
    }
}

/// Build a compile-time fixed tag from a byte array.
pub const fn fixed_tag<const N: usize>(bytes: &[u8; N]) -> Tag<N> {
    FixedBytes(*bytes)
}

/// Return canonical bytes with one encoded field zeroed.
///
/// Fact layouts use this for signatures that cover every field except the
/// signature field itself. Core does not know what the bytes mean; the owning
/// layout chooses the already-encoded fact bytes and exact field range.
pub fn canonical_with_zeroed_field(
    bytes: &[u8],
    zeroed_field: Range<usize>,
) -> Result<Vec<u8>, WireError> {
    if zeroed_field.start > zeroed_field.end || zeroed_field.end > bytes.len() {
        return Err(WireError::WrongLength {
            expected: bytes.len(),
            actual: zeroed_field.end,
        });
    }
    let mut canonical = bytes.to_vec();
    canonical[zeroed_field].fill(0);
    Ok(canonical)
}

/// Require an exact byte length.
pub fn expect_len(bytes: &[u8], expected: usize) -> Result<(), WireError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(WireError::WrongLength {
            expected,
            actual: bytes.len(),
        })
    }
}

fn validate_zero_padding(bytes: &[u8], len: usize) -> Result<(), WireError> {
    if let Some(offset) = bytes[len..].iter().position(|byte| *byte != 0) {
        Err(WireError::NonZeroPadding {
            index: len + offset,
        })
    } else {
        Ok(())
    }
}

fn boxed_zeroed_array<const N: usize>() -> Box<[u8; N]> {
    vec![0; N]
        .into_boxed_slice()
        .try_into()
        .ok()
        .expect("boxed slice length matches requested array length")
}

/// Encode a single byte into an exact-width buffer.
pub fn put_u8(value: u8, out: &mut [u8]) -> Result<(), WireError> {
    expect_len(out, U8_BYTES)?;
    out[0] = value;
    Ok(())
}

/// Decode a single byte from an exact-width buffer.
pub fn take_u8(bytes: &[u8]) -> Result<u8, WireError> {
    expect_len(bytes, U8_BYTES)?;
    Ok(bytes[0])
}

/// Encode a big-endian `u16` into an exact-width buffer.
pub fn put_u16be(value: u16, out: &mut [u8]) -> Result<(), WireError> {
    expect_len(out, U16_BYTES)?;
    out.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

/// Decode a big-endian `u16` from an exact-width buffer.
pub fn take_u16be(bytes: &[u8]) -> Result<u16, WireError> {
    expect_len(bytes, U16_BYTES)?;
    let mut out = [0; U16_BYTES];
    out.copy_from_slice(bytes);
    Ok(u16::from_be_bytes(out))
}

/// Encode a big-endian `u32` into an exact-width buffer.
pub fn put_u32be(value: u32, out: &mut [u8]) -> Result<(), WireError> {
    expect_len(out, U32_BYTES)?;
    out.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

/// Decode a big-endian `u32` from an exact-width buffer.
pub fn take_u32be(bytes: &[u8]) -> Result<u32, WireError> {
    expect_len(bytes, U32_BYTES)?;
    let mut out = [0; U32_BYTES];
    out.copy_from_slice(bytes);
    Ok(u32::from_be_bytes(out))
}

/// Encode a big-endian `u64` into an exact-width buffer.
pub fn put_u64be(value: u64, out: &mut [u8]) -> Result<(), WireError> {
    expect_len(out, U64_BYTES)?;
    out.copy_from_slice(&value.to_be_bytes());
    Ok(())
}

/// Decode a big-endian `u64` from an exact-width buffer.
pub fn take_u64be(bytes: &[u8]) -> Result<u64, WireError> {
    expect_len(bytes, U64_BYTES)?;
    let mut out = [0; U64_BYTES];
    out.copy_from_slice(bytes);
    Ok(u64::from_be_bytes(out))
}

/// Encode a boolean as one byte: `0` or `1`.
pub fn put_bool8(value: bool, out: &mut [u8]) -> Result<(), WireError> {
    put_u8(u8::from(value), out)
}

/// Decode a one-byte boolean and reject any value other than `0` or `1`.
pub fn take_bool8(bytes: &[u8]) -> Result<bool, WireError> {
    match take_u8(bytes)? {
        0 => Ok(false),
        1 => Ok(true),
        actual => Err(WireError::InvalidBool { actual }),
    }
}

/// Sequential wire encoder.
///
/// `Writer` performs only mechanical length checks. Callers still own semantic
/// validation before choosing what to write.
#[derive(Debug, Clone)]
pub struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    /// Build an empty writer.
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Build an empty writer with reserved capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    /// Append one raw byte.
    pub fn u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    /// Append one boolean byte.
    pub fn bool8(&mut self, value: bool) {
        self.u8(u8::from(value));
    }

    /// Append a big-endian `u16`.
    pub fn u16be(&mut self, value: u16) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Append a big-endian `u32`.
    pub fn u32be(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Append a big-endian `u64`.
    pub fn u64be(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    /// Append raw bytes.
    pub fn bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    /// Append a `u16` length prefix followed by bytes.
    pub fn bytes_u16be(&mut self, bytes: &[u8]) -> Result<(), WireError> {
        let len = u16::try_from(bytes.len()).map_err(|_| WireError::ValueTooLarge {
            max: u16::MAX as usize,
            actual: bytes.len(),
        })?;
        self.u16be(len);
        self.bytes(bytes);
        Ok(())
    }

    /// Append a `u32` length prefix followed by bytes.
    pub fn bytes_u32be(&mut self, bytes: &[u8]) -> Result<(), WireError> {
        let len = u32::try_from(bytes.len()).map_err(|_| WireError::ValueTooLarge {
            max: u32::MAX as usize,
            actual: bytes.len(),
        })?;
        self.u32be(len);
        self.bytes(bytes);
        Ok(())
    }

    /// Append a UTF-8 string with a `u16` length prefix.
    pub fn string_u16be(&mut self, value: &str) -> Result<(), WireError> {
        self.bytes_u16be(value.as_bytes())
    }

    /// Append a UTF-8 string with a `u32` length prefix.
    pub fn string_u32be(&mut self, value: &str) -> Result<(), WireError> {
        self.bytes_u32be(value.as_bytes())
    }

    /// Append a fixed-size byte array.
    pub fn fixed<const N: usize>(&mut self, bytes: &[u8; N]) {
        self.bytes.extend_from_slice(bytes);
    }

    /// Append a bounded padded slot.
    pub fn fixed_slot<const N: usize>(&mut self, bytes: &[u8]) -> Result<(), WireError> {
        let slot = FixedSlot::<N>::new(bytes)?;
        self.fixed_slot_value(&slot)
    }

    /// Append an already validated bounded padded slot.
    pub fn fixed_slot_value<const N: usize>(
        &mut self,
        slot: &FixedSlot<N>,
    ) -> Result<(), WireError> {
        let mut encoded = vec![0; FixedSlot::<N>::LEN];
        slot.encode(&mut encoded)?;
        self.bytes.extend_from_slice(&encoded);
        Ok(())
    }

    /// Return the encoded bytes without an exact-length check.
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }

    /// Return the encoded bytes after checking the final length.
    pub fn finish_exact(self, expected: usize) -> Result<Vec<u8>, WireError> {
        expect_len(&self.bytes, expected)?;
        Ok(self.bytes)
    }
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

/// Sequential wire decoder.
///
/// `Reader` advances monotonically through a borrowed byte slice. Call
/// `finish` when the layout expects complete consumption.
#[derive(Debug, Clone, Copy)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    /// Build a reader over borrowed bytes.
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    /// Require the whole input to have an exact length.
    pub fn expect_len(&self, expected: usize) -> Result<(), WireError> {
        expect_len(self.bytes, expected)
    }

    /// Read one byte.
    pub fn u8(&mut self) -> Result<u8, WireError> {
        take_u8(self.take(U8_BYTES)?)
    }

    /// Read a one-byte boolean.
    pub fn bool8(&mut self) -> Result<bool, WireError> {
        take_bool8(self.take(U8_BYTES)?)
    }

    /// Read one byte and require it to match `expected`.
    pub fn expect_u8(&mut self, expected: u8) -> Result<(), WireError> {
        let actual = self.u8()?;
        if actual == expected {
            Ok(())
        } else {
            Err(WireError::UnexpectedU8 { expected, actual })
        }
    }

    /// Read a big-endian `u16`.
    pub fn u16be(&mut self) -> Result<u16, WireError> {
        take_u16be(self.take(U16_BYTES)?)
    }

    /// Read a big-endian `u32`.
    pub fn u32be(&mut self) -> Result<u32, WireError> {
        take_u32be(self.take(U32_BYTES)?)
    }

    /// Read a big-endian `u64`.
    pub fn u64be(&mut self) -> Result<u64, WireError> {
        take_u64be(self.take(U64_BYTES)?)
    }

    /// Read a fixed-size byte array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        Ok(FixedBytes::<N>::decode(self.take(N)?)?.0)
    }

    /// Read a bounded padded slot and return its logical bytes.
    pub fn fixed_slot<const N: usize>(&mut self) -> Result<Vec<u8>, WireError> {
        Ok(FixedSlot::<N>::decode(self.take(FixedSlot::<N>::LEN)?)?
            .bytes()
            .to_vec())
    }

    /// Read a bounded padded slot and return the fixed slot value.
    pub fn fixed_slot_value<const N: usize>(&mut self) -> Result<FixedSlot<N>, WireError> {
        FixedSlot::<N>::decode(self.take(FixedSlot::<N>::LEN)?)
    }

    /// Read `len` raw bytes.
    pub fn bytes(&mut self, len: usize) -> Result<&'a [u8], WireError> {
        self.take(len)
    }

    /// Read bytes prefixed by a big-endian `u16` length.
    pub fn bytes_u16be(&mut self) -> Result<&'a [u8], WireError> {
        let len = self.u16be()? as usize;
        self.take(len)
    }

    /// Read bytes prefixed by a big-endian `u32` length.
    pub fn bytes_u32be(&mut self) -> Result<&'a [u8], WireError> {
        let len = self.u32be()? as usize;
        self.take(len)
    }

    /// Read a UTF-8 string prefixed by a big-endian `u16` length.
    pub fn string_u16be(&mut self) -> Result<String, WireError> {
        let bytes = self.bytes_u16be()?;
        String::from_utf8(bytes.to_vec()).map_err(|_| WireError::InvalidUtf8)
    }

    /// Read a UTF-8 string prefixed by a big-endian `u32` length.
    pub fn string_u32be(&mut self) -> Result<String, WireError> {
        let bytes = self.bytes_u32be()?;
        String::from_utf8(bytes.to_vec()).map_err(|_| WireError::InvalidUtf8)
    }

    /// Require that the reader consumed the whole input.
    pub fn finish(self) -> Result<(), WireError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(WireError::WrongLength {
                expected: self.offset,
                actual: self.bytes.len(),
            })
        }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], WireError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(WireError::ValueTooLarge {
                max: usize::MAX,
                actual: len,
            })?;
        if end > self.bytes.len() {
            return Err(WireError::WrongLength {
                expected: end,
                actual: self.bytes.len(),
            });
        }
        let out = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_bytes_reject_wrong_lengths() {
        assert_eq!(
            FixedBytes::<32>::decode(&[0; 31]).unwrap_err(),
            WireError::WrongLength {
                expected: 32,
                actual: 31
            }
        );
        assert_eq!(
            FixedBytes::<32>::decode(&[0; 33]).unwrap_err(),
            WireError::WrongLength {
                expected: 32,
                actual: 33
            }
        );
        assert!(FixedBytes::<32>::decode(&[0; 32]).is_ok());
    }

    #[test]
    fn fixed_layout_types_reject_wrong_lengths() {
        assert!(take_u8(&[]).is_err());
        assert!(take_u16be(&[0]).is_err());
        assert!(take_u32be(&[0; 3]).is_err());
        assert!(take_u64be(&[0; 7]).is_err());
        assert!(take_bool8(&[0, 0]).is_err());

        let slot = FixedSlot::<3>::new(b"abc").unwrap();
        let mut short = [0; FixedSlot::<3>::LEN - 1];
        assert!(slot.encode(&mut short).is_err());
        assert!(FixedSlot::<3>::decode(&[0; FixedSlot::<3>::LEN + 1]).is_err());
    }

    #[test]
    fn big_endian_values_round_trip() {
        let mut out = [0; U64_BYTES];

        put_u16be(0x1234, &mut out[..U16_BYTES]).unwrap();
        assert_eq!(&out[..U16_BYTES], &[0x12, 0x34]);
        assert_eq!(take_u16be(&out[..U16_BYTES]).unwrap(), 0x1234);

        put_u32be(0x1234_5678, &mut out[..U32_BYTES]).unwrap();
        assert_eq!(&out[..U32_BYTES], &[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(take_u32be(&out[..U32_BYTES]).unwrap(), 0x1234_5678);

        put_u64be(0x1234_5678_9abc_def0, &mut out).unwrap();
        assert_eq!(&out, &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]);
        assert_eq!(take_u64be(&out).unwrap(), 0x1234_5678_9abc_def0);

        put_u64be(42, &mut out).unwrap();
        assert_eq!(take_u64be(&out).unwrap(), 42);
    }

    #[test]
    fn u8_and_bool8_round_trip() {
        let mut out = [0; U8_BYTES];

        put_u8(7, &mut out).unwrap();
        assert_eq!(take_u8(&out).unwrap(), 7);

        put_bool8(true, &mut out).unwrap();
        assert_eq!(out, [1]);
        assert!(take_bool8(&out).unwrap());

        put_bool8(false, &mut out).unwrap();
        assert_eq!(out, [0]);
        assert!(!take_bool8(&out).unwrap());

        assert_eq!(
            take_bool8(&[2]).unwrap_err(),
            WireError::InvalidBool { actual: 2 }
        );
    }

    #[test]
    fn fixed_slot_round_trips_with_zero_padding() {
        let slot = FixedSlot::<5>::new(b"abc").unwrap();
        let mut out = [0xff; FixedSlot::<5>::LEN];

        slot.encode(&mut out).unwrap();
        assert_eq!(&out, &[0, 0, 0, 3, b'a', b'b', b'c', 0, 0]);

        let decoded = FixedSlot::<5>::decode(&out).unwrap();
        assert_eq!(decoded.len(), 3);
        assert_eq!(decoded.bytes(), b"abc");
        assert_eq!(decoded.padded_bytes(), &[b'a', b'b', b'c', 0, 0]);
    }

    #[test]
    fn fixed_slot_rejects_overflow_and_non_zero_padding() {
        assert_eq!(
            FixedSlot::<2>::new(b"abc").unwrap_err(),
            WireError::ValueTooLarge { max: 2, actual: 3 }
        );

        let mut out = [0; FixedSlot::<4>::LEN];
        put_u32be(2, &mut out[..U32_BYTES]).unwrap();
        out[U32_BYTES..].copy_from_slice(&[b'a', b'b', 0, 1]);
        assert_eq!(
            FixedSlot::<4>::decode(&out).unwrap_err(),
            WireError::NonZeroPadding { index: 3 }
        );

        put_u32be(5, &mut out[..U32_BYTES]).unwrap();
        assert_eq!(
            FixedSlot::<4>::decode(&out).unwrap_err(),
            WireError::ValueTooLarge { max: 4, actual: 5 }
        );
    }

    #[test]
    fn fixed_tag_wraps_fixed_bytes() {
        const TAG: Tag<3> = fixed_tag(b"abc");

        let mut out = [0; Tag::<3>::LEN];
        TAG.encode(&mut out).unwrap();
        assert_eq!(out, *b"abc");
    }
}
