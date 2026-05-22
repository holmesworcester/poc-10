//! Content file slice fact family.
//!
//! File slices carry encrypted byte ranges for a file whose metadata lives in a
//! `content::file` fact. Projection validates slice metadata against file
//! context and publishes ordered slice rows. This module owns slice layout and
//! row materialization; higher-level file selection and output live in
//! `content::file` queries and CLI helpers.

pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_CONTENT_FILE_SLICE: u8 = layout::TYPE_CONTENT_FILE_SLICE;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ContentFileSliceFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::ContentFileSliceFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
