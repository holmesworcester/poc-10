//! Content file metadata fact family.
//!
//! A file fact describes the encrypted file object attached to a message:
//! workspace, message, author, root hash, slice count, and sealed metadata.
//! File slices carry the bytes separately. Projection waits for message,
//! signer, deletion, and auth key-material context before publishing file rows used by
//! file queries and save flows.

pub mod adapt;
pub mod authenticate;
pub mod author;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

pub(crate) use decode::Codec;

pub const TYPE_CONTENT_FILE: u8 = encode::TYPE_CONTENT_FILE;

pub const FILE_ROWS: crate::core::store::TableName =
    crate::protocol::registry::read_models::FILE_ROWS;
pub(crate) const FILE_KEY_COLUMNS: &[&str] =
    crate::protocol::registry::read_models::CONTENT_FILES.key_columns;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ContentFileFact, String> {
    decode::decode_fact(bytes)
}

pub fn decode_any_fact(fact: &crate::core::facts::Fact) -> Result<fact::ContentFileFact, String> {
    decode_fact_payload(fact.body())
}
