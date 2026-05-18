pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_CONTENT_FILE: u8 = layout::TYPE_CONTENT_FILE;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ContentFileFact, String> {
    layout::decode_fact(bytes)
}
