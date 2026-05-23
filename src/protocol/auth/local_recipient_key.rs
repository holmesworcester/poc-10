//! Local recipient key fact family.
//!
//! A local recipient key holds private material that lets this store unwrap key
//! wraps. Projection proves it matches the shared recipient fact and emits purge
//! work when the recipient key is superseded.

pub mod fact;
pub mod layout;
pub mod project;

pub const TYPE_LOCAL_RECIPIENT_KEY: u8 = layout::TYPE_LOCAL_RECIPIENT_KEY;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::LocalRecipientKeyFact, String> {
    layout::decode_local_recipient_key(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::LocalRecipientKeyFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
