//! Canonical byte encoding for bundled connection-frame wire facts.
//!
//! This file owns byte construction only: the fact tag, the fixed fact width,
//! and the wire encoding of one bundled encrypted connection frame. It does not
//! decode, authenticate, inspect context, or materialize rows.

use crate::protocol::connection_frame_wire as wire;

use super::fact::ConnectionFrameBundleFact;

pub const TYPE_CONNECTION_FRAME_BUNDLE: u8 = 170;
pub const CONNECTION_FRAME_BUNDLE_FACT_BYTES: usize =
    wire::frame_fact_bytes::<{ wire::CONNECTION_FRAME_BUNDLE_WIRE_BYTES }>();

pub fn encode_fact(fact: &ConnectionFrameBundleFact) -> Result<Vec<u8>, String> {
    let encoded = wire::encode_frame_fact(
        TYPE_CONNECTION_FRAME_BUNDLE,
        wire::CONNECTION_FRAME_SIZE_CLASS_BUNDLE,
        &fact.frame,
    )?;
    if encoded.len() != CONNECTION_FRAME_BUNDLE_FACT_BYTES {
        return Err("connection frame bundle fact has wrong length".to_string());
    }
    Ok(encoded)
}
