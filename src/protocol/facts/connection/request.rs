pub mod addr;
pub mod commands;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ConnectionRequestFact, String> {
    layout::decode_fact(bytes)
}
