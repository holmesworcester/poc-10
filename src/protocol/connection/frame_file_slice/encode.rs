//! Canonical byte encoding for file-slice connection-frame wire facts.
//!
//! This file owns byte construction only: the fact tag, the fixed fact width,
//! and the wire encoding of one file-slice encrypted connection frame. It does
//! not decode, authenticate, inspect context, or materialize rows.

use crate::protocol::connection_frame_wire as wire;

use super::fact::ConnectionFrameFileSliceFact;

pub const TYPE_CONNECTION_FRAME_FILE_SLICE: u8 = 169;
pub const CONNECTION_FRAME_FILE_SLICE_FACT_BYTES: usize =
    wire::frame_fact_bytes::<{ wire::CONNECTION_FRAME_FILE_SLICE_WIRE_BYTES }>();

pub fn encode_fact(fact: &ConnectionFrameFileSliceFact) -> Result<Vec<u8>, String> {
    let encoded = wire::encode_frame_fact(
        TYPE_CONNECTION_FRAME_FILE_SLICE,
        wire::CONNECTION_FRAME_SIZE_CLASS_FILE_SLICE,
        &fact.frame,
    )?;
    if encoded.len() != CONNECTION_FRAME_FILE_SLICE_FACT_BYTES {
        return Err("connection frame file-slice fact has wrong length".to_string());
    }
    Ok(encoded)
}
