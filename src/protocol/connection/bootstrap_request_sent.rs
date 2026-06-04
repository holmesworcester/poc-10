//! Local bootstrap request-sent fact family.
//!
//! A `bootstrap_request_sent` fact records the sender-side evidence for a
//! bootstrap request: the semantic request body, the initiator ephemeral secret
//! id it depends on, the peer route, and the exact sealed bytes sent before a
//! connection exists.

pub mod authenticate;
pub mod fact;
pub mod layout;
pub mod project;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::BootstrapRequestSentFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::BootstrapRequestSentFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
