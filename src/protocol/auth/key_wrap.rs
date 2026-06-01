//! Key wrap fact family.
//!
//! A key wrap is deterministic shared encrypted key material for a recipient.
//! It is the raw exception to natural fact signing: projection proves the
//! signer through recipient/frontier/endpoint context instead of a signature
//! field, and duplicate production must produce the same fact id. This family
//! also owns the wrap-source
//! coordinate scheme and the shared projection helpers that recipient-key,
//! key-request, and local-material projection consume. Projection validates
//! signer/recipient/frontier context and emits unwrap work when local recipient
//! material is present.

pub mod authenticate;
pub mod cli;
pub mod commands;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub const TYPE_KEY_WRAP: u8 = layout::TYPE_KEY_WRAP;

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::KeyWrapFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        layout::decode_key_wrap(fact.body())
    }
}
