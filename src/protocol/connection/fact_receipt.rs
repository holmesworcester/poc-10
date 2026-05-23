//! Connection fact-receipt fact family.
//!
//! A fact receipt records that one semantic fact entered this node through the
//! connection protocol. The receipt stores the normalized network origin,
//! local receive time, receive path, and optional connection/request witnesses.
//! It projects a local context offer keyed by the received fact id; the
//! semantic projector for that fact validates the receipt against its own
//! admission policy.

pub mod create;
pub mod fact;
pub mod layout;
pub mod project;

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
