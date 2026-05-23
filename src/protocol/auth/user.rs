//! User identity fact family.
//!
//! User facts establish named users inside a workspace. They are signed,
//! projected after workspace/admin context is available, and published as user
//! rows/context for content authorship, invites, and query display. Keep user
//! naming and admission policy here; endpoint/device facts represent concrete
//! devices for a user.

pub mod cli;
pub mod commands;
pub mod fact;
pub mod layout;
pub mod project;
pub mod queries;
pub mod rows;

pub const TYPE_USER: u8 = layout::TYPE_USER;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::UserFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = crate::protocol::auth::signed_envelope::SignedPayload<fact::UserFact>;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        crate::protocol::auth::signed_envelope::decode_signed_payload(
            fact,
            layout::TYPE_USER,
            "user",
            decode_fact_payload,
        )
    }
}
