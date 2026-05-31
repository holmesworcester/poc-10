//! User invite fact family.
//!
//! User invites authorize a new user to join a workspace. Projection validates
//! signed inviter authority and publishes invite context used by acceptance
//! flows. This module owns user-invite bytes and admission; device invites and
//! accepted membership are separate fact families.

pub mod commands;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_USER_INVITE: u8 = layout::TYPE_USER_INVITE;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::UserInviteFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::UserInviteFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
