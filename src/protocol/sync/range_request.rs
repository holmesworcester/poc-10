//! Sync range-request fact family.
//!
//! Range requests ask a peer to compare or send facts inside a timestamp range.
//! Projection validates the request shape and drives follow-up sync planning.
//! This module owns the range-request bytes; compare creation decides how to
//! respond to mismatched summaries.

pub mod adapt;
pub mod authenticate;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;

pub(crate) use decode::Codec;

pub const TYPE_SYNC_RANGE_REQUEST: u8 = encode::TYPE_SYNC_RANGE_REQUEST;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::SyncRangeRequestFact, String> {
    decode::decode_fact(bytes)
}
