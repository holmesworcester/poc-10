//! Connection response fact family.
//!
//! Responses complete the connection handshake after a request has enough
//! matched context. Projection validates the request side, responder secret,
//! and endpoint relationship, then materializes connection-response rows used
//! by transport and sync. The response intent creates these facts; this module
//! owns their layout and projection semantics.

pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ConnectionResponseFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::ConnectionResponseFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
