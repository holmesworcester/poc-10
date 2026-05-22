//! Transit-received fact family.
//!
//! A transit-received fact records one inbound frame with normalized origin
//! metadata. Projection decodes the frame enough to admit the contained facts
//! and connection provenance, then lets those facts project normally. This is
//! the durable protocol boundary after core has staged opaque network bytes.

pub mod addr;
pub mod fact;
pub mod layout;
pub mod project;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::TransitReceivedFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::TransitReceivedFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
