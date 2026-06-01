//! Workspace admin grant fact family.
//!
//! Admin facts establish authority to manage a workspace. They are signed,
//! projected only after signer/workspace context is proven, and then exposed as
//! context that other auth and content projectors consume. Keep admin
//! authorization in this module; downstream modules should ask for admin
//! context rather than rechecking grant history.

pub mod authenticate;
pub mod cli;
pub mod commands;
pub mod create;
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
    type Payload = fact::AdminFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
