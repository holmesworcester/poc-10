//! Transit frame projection and envelope helpers.
//!
//! Transit frames bundle protocol facts before the bytes enter `core::network`.
//! Inbound frames become ephemeral `TransitInputFact` projection inputs; the
//! transit projector unwraps them using durable context and emits ordinary
//! durable child facts plus `transport::transit_received` provenance. Socket IO
//! belongs in core, while durable meaning belongs in the fact families carried
//! inside the frame or in the receive-provenance facts.

pub mod create;
pub mod fact;
pub mod layout;
pub mod project;

pub use crate::core::wire::FixedLayout as TransitFrameDecode;
pub use create as receive;
pub use layout as frame;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::TransitInputFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::TransitInputFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
