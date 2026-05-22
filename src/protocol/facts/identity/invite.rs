//! Invite secret fact family.
//!
//! Invite secrets are local or scoped capabilities used to bootstrap users,
//! devices, and invite servers. Projection publishes invite context consumed by
//! connection requests and acceptance flows. Keep secret layout and invite
//! command helpers here; accepted membership facts live in `invite_accepted`.

pub mod cli;
pub mod commands;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::InviteSecretFact, String> {
    layout::decode_fact(bytes)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::InviteSecretFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
