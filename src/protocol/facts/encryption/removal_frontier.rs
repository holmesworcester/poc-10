pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_REMOVAL_FRONTIER: u8 = layout::TYPE_REMOVAL_FRONTIER;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::RemovalFrontierFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projection::FactCodec for Codec {
    type Payload = fact::RemovalFrontierFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
