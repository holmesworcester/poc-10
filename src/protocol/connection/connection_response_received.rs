//! Local membership response-received fact family.

pub mod authenticate;
pub mod fact;
pub mod layout;
pub mod project;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ConnectionResponseReceivedFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::ConnectionResponseReceivedFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
