//! Content reaction fact family.
//!
//! Reactions are encrypted, author-scoped child records of messages. Projection
//! waits for message, signer, deletion, and auth key-material context before
//! publishing reaction rows. Keep reaction payload layout and admission here;
//! message projection only provides the parent context that reactions require.

pub mod authenticate;
pub mod create;
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
    decode_fact_payload(fact.body())
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::ContentReactionFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
