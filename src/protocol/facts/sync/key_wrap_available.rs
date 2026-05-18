pub mod fact;
pub mod layout;
pub mod project;

pub const TYPE_KEY_WRAP_AVAILABLE: u8 = layout::TYPE_KEY_WRAP_AVAILABLE;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::KeyWrapAvailableFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projection::FactCodec for Codec {
    type Payload = fact::KeyWrapAvailableFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
