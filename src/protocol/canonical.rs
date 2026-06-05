//! Protocol-local canonical byte helpers.
//!
//! Fact authors and authenticators sometimes need the same canonical bytes with
//! a signature field zeroed. Keep that rule outside individual `encode.rs`
//! files so encoders remain just canonical byte encoders.

use std::ops::Range;

use crate::core::crypto::ED25519_SIGNATURE_BYTES;

pub fn encode_with_zeroed_trailing_signature<T>(
    value: &T,
    encode: fn(&T) -> Result<Vec<u8>, String>,
) -> Result<Vec<u8>, String> {
    let mut bytes = encode(value)?;
    let Some(start) = bytes.len().checked_sub(ED25519_SIGNATURE_BYTES) else {
        return Err("canonical bytes are shorter than trailing signature".to_string());
    };
    bytes[start..].fill(0);
    Ok(bytes)
}

pub fn encode_with_zeroed_fields<T>(
    value: &T,
    encode: fn(&T) -> Result<Vec<u8>, String>,
    ranges: impl IntoIterator<Item = Range<usize>>,
) -> Result<Vec<u8>, String> {
    let mut bytes = encode(value)?;
    for range in ranges {
        if range.start > range.end || range.end > bytes.len() {
            return Err("canonical zeroed field range is outside encoded bytes".to_string());
        }
        bytes[range].fill(0);
    }
    Ok(bytes)
}
