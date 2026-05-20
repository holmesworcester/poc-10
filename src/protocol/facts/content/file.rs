pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_CONTENT_FILE: u8 = layout::TYPE_CONTENT_FILE;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ContentFileFact, String> {
    layout::decode_fact(bytes)
}

pub fn decode_any_fact(fact: &crate::core::facts::Fact) -> Result<fact::ContentFileFact, String> {
    Ok(
        crate::protocol::facts::content::message::authority::decode_raw_or_signed_fact(
            fact,
            layout::TYPE_CONTENT_FILE,
            "content file",
            decode_fact_payload,
        )?
        .payload,
    )
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload =
        crate::protocol::facts::content::message::authority::DecodedFact<fact::ContentFileFact>;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        crate::protocol::facts::content::message::authority::decode_raw_or_signed_fact(
            fact,
            layout::TYPE_CONTENT_FILE,
            "content file",
            decode_fact_payload,
        )
    }
}
