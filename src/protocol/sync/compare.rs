//! Sync compare fact family.
//!
//! Compare facts summarize a timestamp range for one connection. Projection
//! records the inbound compare and emits response work when requested; create
//! helpers build initial compares, split mismatched ranges, and choose exact
//! fact-id sends when a range is small enough. This module owns the negentropy
//! planning surface for sync.

pub mod authenticate;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_SYNC_COMPARE: u8 = layout::TYPE_SYNC_COMPARE;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::SyncCompareFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::SyncCompareFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
