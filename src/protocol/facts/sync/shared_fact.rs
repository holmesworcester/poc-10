pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_SHARED_FACT: u8 = layout::TYPE_SHARED_FACT;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::SharedFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projection::FactCodec for Codec {
    type Payload = fact::SharedFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}

pub use rows::{
    record_shareable_fact, shareable_fact_for_connection, shareable_fact_row, shareable_fact_rows,
    shareable_facts_for_connection, sync_status, ShareableFactRow, SHAREABLE_FACT_ROWS,
};
