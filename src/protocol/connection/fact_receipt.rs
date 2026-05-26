//! Connection fact-receipt family.
//!
//! A fact receipt is durable local evidence that a semantic fact entered this
//! node through the connection protocol. Receipts record normalized origin
//! metadata, receive time, receive path, and optional connection/request
//! witnesses; they publish context keyed by the received fact id.
//!
//! Receipts do not authorize the received payload. The semantic projector for
//! the received fact decides whether the receipt proves the right path. Change
//! this family for receipt bytes, receive-path vocabulary, or receipt context
//! offers.

pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub use rows::origin_connection_ids_for_fact;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ConnectionFactReceipt, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::ConnectionFactReceipt;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
