pub mod cli;
pub mod commands;
pub mod create;
pub mod fact;
pub mod layout;
pub mod local_membership;
pub mod project;
pub mod queries;
pub mod rows;
pub mod runtime_counts;

pub const TYPE_WORKSPACE: u8 = layout::TYPE_WORKSPACE;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::WorkspaceFact, String> {
    layout::decode_fact(bytes)
}
