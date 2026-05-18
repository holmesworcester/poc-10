pub mod authority;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_CONTENT_MESSAGE: u8 = layout::TYPE_CONTENT_MESSAGE;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ContentMessageFact, String> {
    layout::decode_fact(bytes)
}
