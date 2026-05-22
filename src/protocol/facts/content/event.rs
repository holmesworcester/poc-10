//! Generic content event fact family.
//!
//! Content events are test and utility payloads that exercise workspace-scoped
//! shared content without the richer message/file authority model. Commands
//! create them, projection materializes workspace-time rows, and queries expose
//! counts for CLI/reporting flows. Keep message-specific policy out of this
//! module; it belongs under `content::message`.

pub mod cli;
pub mod commands;
pub mod fact;
pub mod layout;
pub mod project;
pub mod queries;
pub mod rows;

pub const TYPE_CONTENT_EVENT: u8 = layout::TYPE_CONTENT_EVENT;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ContentEventFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload =
        crate::protocol::facts::content::message::authority::DecodedFact<fact::ContentEventFact>;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        crate::protocol::facts::content::message::authority::decode_raw_or_signed_fact(
            fact,
            layout::TYPE_CONTENT_EVENT,
            "content event",
            decode_fact_payload,
        )
    }
}
