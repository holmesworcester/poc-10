//! Content message fact family.
//!
//! Messages are the primary user-visible content records. The family is split by
//! pipeline stage: `encode`/`decode` (wire bytes ⟷ typed value), `author` (pure
//! local construction) and `commands` (the runtime entry points that author),
//! `authenticate` (the read gate and write self-check), `adapt` (identity), and
//! `project` (materialization + retention). Other content facts depend on message
//! context rather than duplicating message authority rules.

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
pub mod rows;

pub const TYPE_CONTENT_MESSAGE: u8 = fact::TYPE_CONTENT_MESSAGE;

pub use project::{
    expiration_timeline, retention_floor_need, retention_floor_offer, COVER_HORIZON_MINUTES,
};

pub use decode::decode_fact_payload;
pub(crate) use decode::Codec;
