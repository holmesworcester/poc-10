//! Removal frontier fact family.
//!
//! A removal frontier names the live content-key frontier for a workspace and
//! endpoint. Projection validates owner authority and publishes frontier context
//! that local secrets, key requests, and key wraps depend on.

pub mod create;
pub mod fact;
pub mod layout;
pub mod project;

pub const TYPE_REMOVAL_FRONTIER: u8 = layout::TYPE_REMOVAL_FRONTIER;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::RemovalFrontierFact, String> {
    layout::decode_removal_frontier(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::RemovalFrontierFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
