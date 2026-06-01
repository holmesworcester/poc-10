//! Bundled connection-frame wire fact family.
//!
//! A `connection_frame_bundle` fact is the canonical local fact for one bundled
//! encrypted connection frame. Receive projection pairs it with local
//! `connection_frame_observation` context before opening the frame and emitting
//! durable child facts plus receipts.

pub mod authenticate;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::ConnectionFrameBundleFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        layout::decode_fact(fact.body())
    }
}
