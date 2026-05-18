pub mod commands;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_CONTENT_MESSAGE_DELETION: u8 = layout::TYPE_CONTENT_MESSAGE_DELETION;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ContentMessageDeletionFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projection::FactCodec for Codec {
    type Payload = crate::protocol::facts::content::message::authority::DecodedFact<
        fact::ContentMessageDeletionFact,
    >;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        crate::protocol::facts::content::message::authority::decode_raw_or_signed_fact(
            fact,
            layout::TYPE_CONTENT_MESSAGE_DELETION,
            "message deletion",
            decode_fact_payload,
        )
    }
}
