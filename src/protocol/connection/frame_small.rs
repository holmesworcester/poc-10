//! Small connection-frame receive fact family.
//!
//! A `connection_frame_small` fact is local ephemeral input for one received
//! small encrypted connection frame. Projection opens the frame with local
//! connection context and emits durable child facts plus receipts.

pub mod fact;
pub mod layout;
pub mod project;

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::ConnectionFrameSmallFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        layout::decode_fact(fact.body())
    }
}
