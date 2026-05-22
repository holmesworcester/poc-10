//! Content message fact family.
//!
//! Messages are the primary user-visible content records. This module owns the
//! stable message layout, authoring constructors, authority checks for raw or
//! signed payloads, projection into opened-message/tombstone rows, retention
//! scheduling, queries, and CLI formatting. Other content facts depend on
//! message context rather than duplicating message authority rules.

pub mod authoring;
pub mod authority;
pub mod cli;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod queries;
pub mod retention;
pub mod rows;

pub const TYPE_CONTENT_MESSAGE: u8 = layout::TYPE_CONTENT_MESSAGE;

pub fn expiration_timeline() -> crate::core::projectors::Timeline {
    crate::core::projectors::Timeline::new("content_message_expiry")
        .expect("valid content-message expiry timeline")
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ContentMessageFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload =
        crate::protocol::content::message::authority::DecodedFact<fact::ContentMessageFact>;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        authority::decode_raw_or_signed_fact(
            fact,
            layout::TYPE_CONTENT_MESSAGE,
            "content message",
            decode_fact_payload,
        )
    }
}
