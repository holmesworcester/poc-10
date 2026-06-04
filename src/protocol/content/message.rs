//! Content message fact family.
//!
//! Messages are the primary user-visible content records. This module owns the
//! stable message layout, authoring, authentication, staged adaptation,
//! projection into opened-message/tombstone rows, retention scheduling, queries,
//! and CLI formatting. Authority and retention machinery live in `project`;
//! other content facts depend on message context rather than duplicating message
//! authority rules.

pub mod adapt;
pub mod authenticate;
pub mod author;
pub mod cli;
pub mod commands;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

pub const TYPE_CONTENT_MESSAGE: u8 = encode::TYPE_CONTENT_MESSAGE;

pub(crate) use decode::Codec;

pub use project::{
    expiration_timeline, retention_floor_need, retention_floor_offer, COVER_HORIZON_MINUTES,
};

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ContentMessageFact, String> {
    decode::decode_fact(bytes)
}
