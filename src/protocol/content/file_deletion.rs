//! Content file deletion fact family.
//!
//! File deletions are author-signed tombstones for file ids. Commands construct
//! the deletion fact from user selection, projection verifies target and author
//! context, and projection publishes `content_purged` context for the target
//! file coordinate. Keep deletion authorization here; file metadata and slice
//! projection only consume the resulting context and remove their own state.

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

pub(crate) use decode::Codec;

pub const TYPE_CONTENT_FILE_DELETION: u8 = encode::TYPE_CONTENT_FILE_DELETION;

pub const FILE_DELETION_ROWS: crate::core::store::TableName =
    crate::protocol::registry::read_models::FILE_DELETION_ROWS;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ContentFileDeletionFact, String> {
    decode::decode_fact(bytes)
}
