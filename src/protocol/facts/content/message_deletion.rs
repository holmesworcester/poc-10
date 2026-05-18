pub mod commands;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_CONTENT_MESSAGE_DELETION: u8 = layout::TYPE_CONTENT_MESSAGE_DELETION;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ContentMessageDeletionFact, String> {
    layout::decode_fact(bytes)
}
