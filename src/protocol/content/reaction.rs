//! Content reaction fact family.
//!
//! Reactions are encrypted, author-scoped child records of messages. Projection
//! waits for message, signer, deletion, and auth key-material context before
//! publishing reaction rows. Keep reaction payload layout and admission here;
//! message projection only provides the parent context that reactions require.

pub mod adapt;
pub mod authenticate;
pub mod author;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

pub(crate) use decode::Codec;

use crate::core::store::TableName;

pub const REACTION_ROWS: TableName = crate::protocol::registry::read_models::REACTION_ROWS;

pub const TYPE_CONTENT_REACTION: u8 = encode::TYPE_CONTENT_REACTION;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ContentReactionFact, String> {
    decode::decode_fact(bytes)
}

pub fn decode_any_fact(
    fact: &crate::core::facts::Fact,
) -> Result<fact::ContentReactionFact, String> {
    decode_fact_payload(fact.body())
}
