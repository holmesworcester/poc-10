//! Recipient key fact family.
//!
//! A recipient key names an endpoint public key eligible to receive workspace
//! auth key material. Projection validates supersession and emits proactive
//! key-wrap work.

pub mod fact;
pub mod layout;
pub mod project;

pub const TYPE_RECIPIENT_KEY: u8 = layout::TYPE_RECIPIENT_KEY;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::RecipientKeyFact, String> {
    layout::decode_recipient_key(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::RecipientKeyFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
