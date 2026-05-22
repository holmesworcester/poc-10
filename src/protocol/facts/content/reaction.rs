//! Content reaction fact family.
//!
//! Reactions are encrypted, author-scoped child records of messages. Projection
//! waits for message, signer, deletion, and encryption context before
//! publishing reaction rows. Keep reaction payload layout and admission here;
//! message projection only provides the parent context that reactions require.

pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_CONTENT_REACTION: u8 = layout::TYPE_CONTENT_REACTION;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ContentReactionFact, String> {
    layout::decode_fact(bytes)
}

pub fn decode_any_fact(
    fact: &crate::core::facts::Fact,
) -> Result<fact::ContentReactionFact, String> {
    Ok(
        crate::protocol::facts::content::message::authority::decode_raw_or_signed_fact(
            fact,
            layout::TYPE_CONTENT_REACTION,
            "reaction",
            decode_fact_payload,
        )?
        .payload,
    )
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload =
        crate::protocol::facts::content::message::authority::DecodedFact<fact::ContentReactionFact>;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        crate::protocol::facts::content::message::authority::decode_raw_or_signed_fact(
            fact,
            layout::TYPE_CONTENT_REACTION,
            "reaction",
            decode_fact_payload,
        )
    }
}
