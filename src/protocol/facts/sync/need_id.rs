pub mod create;
pub mod fact;
pub mod layout;
pub mod project;

pub const TYPE_SYNC_NEED_ID: u8 = layout::TYPE_SYNC_NEED_ID;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::SyncNeedIdFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::SyncNeedIdFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
pub mod rows;
