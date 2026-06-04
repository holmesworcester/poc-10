//! Local bootstrap response-received fact family.

pub mod authenticate;
pub mod fact;
pub mod layout;
pub mod project;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::BootstrapResponseReceivedFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::BootstrapResponseReceivedFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
