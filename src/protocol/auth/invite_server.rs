//! Invite-server fact family.
//!
//! Invite-server facts advertise a server endpoint that can help bootstrap
//! connection requests. They are signed, projected through auth authority
//! context, and exposed as invite-server rows plus context for connection
//! handshakes. Keep server advertisement policy here, not in network send handlers.

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
    type Payload = fact::InviteServerFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
