//! Content file slice fact family.
//!
//! File slices carry encrypted byte ranges for a file whose metadata lives in a
//! `content::file` fact. Projection validates slice metadata against file
//! context and publishes ordered slice rows. This module owns slice layout and
//! row materialization; higher-level file selection and output live in
//! `content::file` queries and CLI helpers.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

pub const TYPE_CONTENT_FILE_SLICE: u8 = encode::TYPE_CONTENT_FILE_SLICE;

pub const FILE_SLICE_ROWS: crate::core::db::TableName =
    crate::protocol::registry::read_models::FILE_SLICE_ROWS;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ContentFileSliceFact, String> {
    project::decode::decode_fact(bytes)
}
