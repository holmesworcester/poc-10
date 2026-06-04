//! File-slice connection-frame wire fact family.
//!
//! A `connection_frame_file_slice` fact is local ephemeral input for one
//! encrypted connection frame sized for a content file slice. Receive
//! projection pairs it with local `connection_frame_observation` context before
//! opening the frame and emitting durable child facts plus receipts.

pub mod authenticate;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;

pub(crate) struct Codec;

impl crate::core::pipeline::FactCodec for Codec {
    type Payload = fact::ConnectionFrameFileSliceFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        layout::decode_fact(fact.body())
    }
}
