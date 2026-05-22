//! Content file deletion fact family.
//!
//! File deletions are author-signed tombstones for file ids. Commands construct
//! the deletion fact from user selection, projection verifies target and author
//! context, and rows mark the file deleted without mutating the original file
//! fact. Keep deletion authorization here; file metadata projection should only
//! consume the resulting deletion context.

pub mod cli;
pub mod commands;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_CONTENT_FILE_DELETION: u8 = layout::TYPE_CONTENT_FILE_DELETION;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ContentFileDeletionFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = crate::protocol::facts::content::message::authority::DecodedFact<
        fact::ContentFileDeletionFact,
    >;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        crate::protocol::facts::content::message::authority::decode_raw_or_signed_fact(
            fact,
            layout::TYPE_CONTENT_FILE_DELETION,
            "file deletion",
            decode_fact_payload,
        )
    }
}
