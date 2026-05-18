pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_INVITE_SERVER: u8 = layout::TYPE_INVITE_SERVER;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::InviteServerFact, String> {
    layout::decode_fact(bytes)
}
