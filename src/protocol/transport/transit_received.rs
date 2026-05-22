//! Transit-received fact family.
//!
//! A transit-received fact records one inbound frame with normalized origin
//! metadata and projects a local context offer keyed by the received fact id.
//! The receive handler opens frames and admits payload facts; this family only
//! owns the durable provenance proof that other projectors validate.

pub mod create;
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
