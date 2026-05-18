pub mod cli;
pub mod commands;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::InviteSecretFact, String> {
    layout::decode_fact(bytes)
}
