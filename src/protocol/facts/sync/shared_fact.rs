pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_SHARED_FACT: u8 = layout::TYPE_SHARED_FACT;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::SharedFact, String> {
    layout::decode_fact(bytes)
}

pub use rows::{
    record_shareable_fact, shareable_fact_for_connection, shareable_fact_row, shareable_fact_rows,
    shareable_facts_for_connection, sync_status, ShareableFactRow, SHAREABLE_FACT_ROWS,
};
