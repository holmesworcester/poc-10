//! Key wrap fact family.
//!
//! A key wrap is a signed-envelope fact carrying encrypted key material for a
//! recipient. This family also owns the wrap-source coordinate scheme and the
//! shared projection helpers that recipient-key, key-request, and local-material
//! projection consume. Projection validates signer/recipient/frontier context
//! and emits unwrap work when local recipient material is present.

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
    type Payload = crate::protocol::identity::signed_fact::SignedPayload<fact::KeyWrapFact>;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        crate::protocol::identity::signed_fact::decode_signed_fact_payload(
            fact,
            layout::TYPE_KEY_WRAP,
            "encryption key wrap",
            layout::decode_key_wrap,
        )
    }
}
