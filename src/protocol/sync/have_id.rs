//! Sync have-id fact family.
//!
//! A have-id fact tells a peer that this connection can provide a specific
//! fact id at a timestamp. Projection records the advertisement and wakes any
//! matching need-id flow. The helper here builds advertisements from already
//! stored facts; it does not validate the advertised fact's own protocol
//! semantics.

pub mod authenticate;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub use create::advertisement_fact;

pub const TYPE_SYNC_HAVE_ID: u8 = layout::TYPE_SYNC_HAVE_ID;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::SyncHaveIdFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::SyncHaveIdFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
