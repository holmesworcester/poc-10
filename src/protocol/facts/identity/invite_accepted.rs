pub mod commands;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_INVITE_ACCEPTED: u8 = layout::TYPE_INVITE_ACCEPTED;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::InviteAcceptedFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projection::FactCodec for Codec {
    type Payload = fact::InviteAcceptedFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
