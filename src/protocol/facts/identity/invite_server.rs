pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_INVITE_SERVER: u8 = layout::TYPE_INVITE_SERVER;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::InviteServerFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload =
        crate::protocol::facts::identity::signed_fact::SignedPayload<fact::InviteServerFact>;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        crate::protocol::facts::identity::signed_fact::decode_signed_fact_payload(
            fact,
            layout::TYPE_INVITE_SERVER,
            "invite_server",
            decode_fact_payload,
        )
    }
}
