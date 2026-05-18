pub mod authority;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_CONTENT_MESSAGE: u8 = layout::TYPE_CONTENT_MESSAGE;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ContentMessageFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projection::FactCodec for Codec {
    type Payload =
        crate::protocol::facts::content::message::authority::DecodedFact<fact::ContentMessageFact>;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        authority::decode_raw_or_signed_fact(
            fact,
            layout::TYPE_CONTENT_MESSAGE,
            "content message",
            decode_fact_payload,
        )
    }
}
