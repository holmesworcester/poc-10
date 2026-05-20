pub mod commands;
pub mod fact;
pub mod layout;
pub mod local_endpoint;
pub mod project;
pub mod queries;
pub mod rows;

pub const TYPE_LOCAL_ENDPOINT: u8 = layout::TYPE_LOCAL_ENDPOINT;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::EndpointFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::EndpointFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
