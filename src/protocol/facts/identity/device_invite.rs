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
    type Payload =
        crate::protocol::facts::identity::signed_fact::SignedPayload<fact::DeviceInviteFact>;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        crate::protocol::facts::identity::signed_fact::decode_signed_fact_payload(
            fact,
            layout::TYPE_DEVICE_INVITE,
            "device_invite",
            decode_fact_payload,
        )
    }
}
