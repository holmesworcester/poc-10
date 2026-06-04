//! User identity fact family.
//!
//! User facts establish named users inside a workspace. They are signed,
//! projected after workspace/admin context is available, and published as user
//! rows/context for content authorship, invites, and query display. Keep user
//! naming and admission policy here; endpoint/device facts represent concrete
//! devices for a user.

pub mod authenticate;
pub mod cli;
pub mod commands;
pub mod create;
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

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = fact::UserFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
