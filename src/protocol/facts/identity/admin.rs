pub mod cli;
pub mod commands;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_ADMIN: u8 = layout::TYPE_ADMIN;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::AdminFact, String> {
    layout::decode_fact(bytes)
}

pub fn encode_fact_payload(fact: &fact::AdminFact) -> Result<Vec<u8>, String> {
    layout::encode_fact(fact)
}
