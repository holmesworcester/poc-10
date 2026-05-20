pub mod cli;
pub mod commands;
pub mod fact;
pub mod layout;
pub mod project;
pub mod queries;
pub mod rows;

pub const TYPE_USER: u8 = layout::TYPE_USER;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::UserFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = crate::protocol::facts::identity::signed_fact::SignedPayload<fact::UserFact>;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        crate::protocol::facts::identity::signed_fact::decode_signed_fact_payload(
            fact,
            layout::TYPE_USER,
            "user",
            decode_fact_payload,
        )
    }
}
