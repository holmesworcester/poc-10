//! Content message fact family.
//!
//! Messages are the primary user-visible content records. This module owns the
//! stable message layout, authoring constructors (`create`), authority checks
//! for signed payloads, projection into opened-message/tombstone rows,
//! retention scheduling, queries, and CLI formatting. Authority and retention
//! machinery live in `project`; other content facts depend on message context
//! rather than duplicating message authority rules.

pub mod authenticate;
pub mod cli;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod queries;
pub mod rows;

pub const TYPE_CONTENT_MESSAGE: u8 = layout::TYPE_CONTENT_MESSAGE;

pub use project::{
    expiration_timeline, retention_floor_need, retention_floor_offer, COVER_HORIZON_MINUTES,
};

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ContentMessageFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::ContentMessageFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
