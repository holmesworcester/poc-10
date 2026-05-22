//! Workspace admin grant fact family.
//!
//! Admin facts establish authority to manage a workspace. They are signed,
//! projected only after signer/workspace context is proven, and then exposed as
//! context that other identity and content projectors consume. Keep admin
//! authorization in this module; downstream modules should ask for admin
//! context rather than rechecking grant history.

pub mod cli;
pub mod commands;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_ADMIN: u8 = layout::TYPE_ADMIN;

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::AdminFact, String> {
    layout::decode_fact(bytes)
}

pub fn encode_fact_payload(fact: &fact::AdminFact) -> Result<Vec<u8>, String> {
    layout::encode_fact(fact)
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = crate::protocol::facts::identity::signed_fact::SignedPayload<fact::AdminFact>;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        crate::protocol::facts::identity::signed_fact::decode_signed_fact_payload(
            fact,
            layout::TYPE_ADMIN,
            "admin",
            decode_fact_payload,
        )
    }
}
