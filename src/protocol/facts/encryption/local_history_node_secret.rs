pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_LOCAL_HISTORY_NODE_SECRET: u8 = layout::TYPE_LOCAL_HISTORY_NODE_SECRET;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::LocalHistoryNodeSecretFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::LocalHistoryNodeSecretFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
