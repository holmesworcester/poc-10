pub mod cli;
pub mod commands;
pub mod fact;
pub mod layout;
pub mod project;
pub mod queries;
pub mod rows;

pub const TYPE_USER: u8 = layout::TYPE_USER;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::UserFact, String> {
    layout::decode_fact(bytes)
}
