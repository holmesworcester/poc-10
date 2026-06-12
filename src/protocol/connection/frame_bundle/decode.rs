//! Byte decoding for bundle connection-frame wire facts.
//!
//! Decoding proves only the fixed layout: tag, length, and the embedded frame
//! shape. Id checks live in `authenticate.rs`.

use crate::core::facts::FactId;
use crate::core::wire::{self, FixedLayout, Id32, Nonce24, Tag, WireError};

use super::encode::{
    wire_err, ConnectionFrameBundleV1, CIPHERTEXT_OFFSET, CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES,
    CONNECTION_FRAME_BUNDLE_FACT_BYTES, CONNECTION_FRAME_BUNDLE_WIRE_BYTES,
    CONNECTION_FRAME_HEADER_BYTES, CONNECTION_FRAME_SIZE_CLASS_BUNDLE, CONNECTION_FRAME_TAG,
    CONNECTION_FRAME_VERSION, TYPE_CONNECTION_FRAME_BUNDLE,
};
use super::fact::ConnectionFrameBundleFact;

/// Public header view recovered without decrypting the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFrameHeader {
    pub connection_id: Id32,
    pub nonce: Nonce24,
}

/// Borrowed bundle frame payload recovered without materializing a large fixed
/// slot value on the stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFrameParts<'a> {
    pub header: ConnectionFrameHeader,
    pub ciphertext: &'a [u8],
}

const VERSION_OFFSET: usize = Tag::<4>::LEN;
const SIZE_CLASS_OFFSET: usize = VERSION_OFFSET + wire::U8_BYTES;
const CONNECTION_OFFSET: usize = SIZE_CLASS_OFFSET + wire::U8_BYTES;
const NONCE_OFFSET: usize = CONNECTION_OFFSET + Id32::LEN;

pub fn decode_fact(bytes: &[u8]) -> Result<ConnectionFrameBundleFact, String> {
    if bytes.len() != CONNECTION_FRAME_BUNDLE_FACT_BYTES {
        return Err("connection frame bundle fact has wrong length".to_string());
    }
    let mut reader = wire::Reader::new(bytes);
    reader
        .expect_len(CONNECTION_FRAME_BUNDLE_FACT_BYTES)
        .map_err(wire_err)?;
    reader
        .expect_u8(TYPE_CONNECTION_FRAME_BUNDLE)
        .map_err(wire_err)?;
    let frame = reader
        .fixed_slot_value::<CONNECTION_FRAME_BUNDLE_WIRE_BYTES>()
        .map_err(wire_err)?;
    reader.finish().map_err(wire_err)?;
    ConnectionFrameBundleV1::decode(frame.bytes()).map_err(wire_err)?;
    Ok(ConnectionFrameBundleFact { frame })
}

pub fn is_frame(bytes: &[u8]) -> bool {
    decode_frame_parts(bytes).is_ok()
}

pub fn received_connection_fact_id(frame: &[u8]) -> Result<FactId, String> {
    Ok(decode_frame_parts(frame)
        .map_err(wire_err)?
        .header
        .connection_id
        .0)
}

/// Inspect the public header of a bundle connection frame.
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
    if size_class != CONNECTION_FRAME_SIZE_CLASS_BUNDLE {
        return Err(WireError::InvalidBool { actual: size_class });
    }
    let connection_id = Id32::decode(&bytes[CONNECTION_OFFSET..NONCE_OFFSET])?;
    let nonce = Nonce24::decode(&bytes[NONCE_OFFSET..CIPHERTEXT_OFFSET])?;
    Ok(ConnectionFrameHeader {
        connection_id,
        nonce,
    })
}

/// Decode the public header and borrowed ciphertext slot for a bundle frame.
pub fn decode_frame_parts(bytes: &[u8]) -> Result<ConnectionFrameParts<'_>, WireError> {
    let header = peek_frame_header(bytes)?;
    if bytes.len() != CONNECTION_FRAME_BUNDLE_WIRE_BYTES {
        return Err(WireError::WrongLength {
            expected: CONNECTION_FRAME_BUNDLE_WIRE_BYTES,
            actual: bytes.len(),
        });
    }
    let slot = &bytes[CIPHERTEXT_OFFSET..];
    let ciphertext_len = wire::take_u32be(&slot[..wire::U32_BYTES])? as usize;
    if ciphertext_len > CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES {
        return Err(WireError::ValueTooLarge {
            max: CONNECTION_FRAME_BUNDLE_CIPHERTEXT_BYTES,
            actual: ciphertext_len,
        });
    }
    if let Some(offset) = slot[wire::U32_BYTES + ciphertext_len..]
        .iter()
        .position(|byte| *byte != 0)
    {
        return Err(WireError::NonZeroPadding {
            index: CIPHERTEXT_OFFSET + wire::U32_BYTES + ciphertext_len + offset,
        });
    }
    Ok(ConnectionFrameParts {
        header,
        ciphertext: &slot[wire::U32_BYTES..wire::U32_BYTES + ciphertext_len],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::wire::{FixedBytes, FixedSlot};
    use crate::protocol::connection::frame_bundle::encode::{
        encode_fact, encode_frame_bytes, CONNECTION_FRAME_BUNDLE_FACT_BYTES,
    };

    #[test]
    fn connection_frame_bundle_fact_roundtrips_fixed_width() {
        let frame =
            encode_frame_bytes(FixedBytes([1; 32]), FixedBytes([2; 24]), &[3; 32]).expect("frame");
        let fact = ConnectionFrameBundleFact {
            frame: FixedSlot::new(&frame).expect("frame slot"),
        };

        let encoded = encode_fact(&fact).expect("encode");

        assert_eq!(encoded.len(), CONNECTION_FRAME_BUNDLE_FACT_BYTES);
        assert_eq!(decode_fact(&encoded).expect("decode"), fact);
    }
}
