//! Sync range-request fact family.
//!
//! Range requests ask a peer to compare or send facts inside a timestamp range.
//! Projection validates the request shape and drives follow-up sync planning.
//! This module owns the range-request bytes; compare creation decides how to
//! respond to mismatched summaries.

pub mod authenticate;
pub mod fact;
pub mod layout;
pub mod project;

pub const TYPE_SYNC_RANGE_REQUEST: u8 = layout::TYPE_SYNC_RANGE_REQUEST;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::SyncRangeRequestFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::SyncRangeRequestFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
