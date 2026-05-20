pub mod cli;
pub mod commands;
pub mod fact;
pub mod layout;
pub mod project;
pub mod queries;
pub mod rows;

pub const TYPE_DISAPPEARING_MESSAGES_SETTING: u8 = layout::TYPE_DISAPPEARING_MESSAGES_SETTING;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::DisappearingMessagesSettingFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::DisappearingMessagesSettingFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
