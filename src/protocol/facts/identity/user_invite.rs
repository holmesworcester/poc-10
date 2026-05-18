pub mod commands;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_USER_INVITE: u8 = layout::TYPE_USER_INVITE;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::UserInviteFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projection::FactCodec for Codec {
    type Payload =
        crate::protocol::facts::identity::signed_fact::SignedPayload<fact::UserInviteFact>;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        crate::protocol::facts::identity::signed_fact::decode_signed_fact_payload(
            fact,
            layout::TYPE_USER_INVITE,
            "user_invite",
            decode_fact_payload,
        )
    }
}
