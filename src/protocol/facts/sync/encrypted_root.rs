pub mod fact;
pub mod layout;
pub mod project;

pub const TYPE_ENCRYPTED_ROOT: u8 = layout::TYPE_ENCRYPTED_ROOT;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::EncryptedRootFact, String> {
    layout::decode_fact(bytes)
}
