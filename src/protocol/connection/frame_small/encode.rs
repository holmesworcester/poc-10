//! Canonical byte encoding for small connection-frame wire facts.
//!
//! This file owns byte construction only: the fact tag, the fixed fact width,
//! and the wire encoding of one small encrypted connection frame. It does not
//! decode, authenticate, inspect context, or materialize rows.

use crate::protocol::connection_frame_wire as wire;

use super::fact::ConnectionFrameSmallFact;

pub const TYPE_CONNECTION_FRAME_SMALL: u8 = 168;
pub const CONNECTION_FRAME_SMALL_FACT_BYTES: usize =
    wire::frame_fact_bytes::<{ wire::CONNECTION_FRAME_SMALL_WIRE_BYTES }>();

pub fn encode_fact(fact: &ConnectionFrameSmallFact) -> Result<Vec<u8>, String> {
    let encoded = wire::encode_frame_fact(
        TYPE_CONNECTION_FRAME_SMALL,
        wire::CONNECTION_FRAME_SIZE_CLASS_SMALL,
        &fact.frame,
    )?;
    if encoded.len() != CONNECTION_FRAME_SMALL_FACT_BYTES {
        return Err("connection frame small fact has wrong length".to_string());
    }
    Ok(encoded)
}
