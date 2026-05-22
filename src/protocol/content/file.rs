//! Content file metadata fact family.
//!
//! A file fact describes the encrypted file object attached to a message:
//! workspace, message, author, root hash, slice count, and sealed metadata.
//! File slices carry the bytes separately. Projection waits for message,
//! signer, deletion, and encryption context before publishing file rows used by
//! file queries and save flows.

pub mod fact;
pub mod layout;
pub mod project;
pub mod queries;
pub mod rows;

pub const TYPE_CONTENT_FILE: u8 = layout::TYPE_CONTENT_FILE;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ContentFileFact, String> {
    layout::decode_fact(bytes)
}

pub fn decode_any_fact(fact: &crate::core::facts::Fact) -> Result<fact::ContentFileFact, String> {
    Ok(
        crate::protocol::content::message::project::decode_raw_or_signed_fact(
            fact,
            layout::TYPE_CONTENT_FILE,
            "content file",
            decode_fact_payload,
        )?
        .payload,
    )
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = crate::protocol::content::message::project::DecodedFact<fact::ContentFileFact>;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        crate::protocol::content::message::project::decode_raw_or_signed_fact(
            fact,
            layout::TYPE_CONTENT_FILE,
            "content file",
            decode_fact_payload,
        )
    }
}
