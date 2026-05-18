pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_DEVICE_INVITE: u8 = layout::TYPE_DEVICE_INVITE;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::DeviceInviteFact, String> {
    layout::decode_fact(bytes)
}
