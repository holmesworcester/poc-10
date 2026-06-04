//! Sync need-id fact family.
//!
//! Need-id facts request a specific fact from a peer after compare or have-id
//! planning discovers a gap. Projection records the request and emits handler
//! work to send the fact when this store has it. The requested payload remains
//! validated by its owning fact family after receipt.

pub mod authenticate;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;

pub const TYPE_SYNC_NEED_ID: u8 = layout::TYPE_SYNC_NEED_ID;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::SyncNeedIdFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = fact::SyncNeedIdFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}

pub mod rows;
