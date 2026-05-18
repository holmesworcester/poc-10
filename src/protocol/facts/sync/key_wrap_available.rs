pub mod fact;
pub mod layout;
pub mod project;

pub const TYPE_KEY_WRAP_AVAILABLE: u8 = layout::TYPE_KEY_WRAP_AVAILABLE;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::KeyWrapAvailableFact, String> {
    layout::decode_fact(bytes)
}
