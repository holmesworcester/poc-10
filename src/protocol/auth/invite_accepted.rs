//! Invite acceptance fact family.
//!
//! Invite-accepted facts turn an invite secret into concrete workspace/user or
//! endpoint membership. Projection validates the invite context and materializes
//! the accepted identity rows/context that later projectors rely on. Commands
//! here create the local facts needed to accept an invite; invite creation stays
//! in `auth::invite`.

pub mod authenticate;
pub mod commands;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_INVITE_ACCEPTED: u8 = layout::TYPE_INVITE_ACCEPTED;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::InviteAcceptedFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = fact::InviteAcceptedFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
