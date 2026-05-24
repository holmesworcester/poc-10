//! Device invite fact family.
//!
//! Device invites let an existing identity authorize another endpoint. The fact
//! is signed, projection verifies the inviter authority, and rows/context expose
//! the invite key for acceptance flows. This module owns device-invite layout
//! and admission; accepting the invite is handled by `invite_accepted`.

pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_DEVICE_INVITE: u8 = layout::TYPE_DEVICE_INVITE;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::DeviceInviteFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::DeviceInviteFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
