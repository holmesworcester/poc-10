//! File-slice connection-frame receive fact family.
//!
//! A `connection_frame_file_slice` fact is local ephemeral input for one
//! received encrypted connection frame sized for a content file slice.
//! Projection opens the frame with local connection context and emits durable
//! child facts plus receipts.

pub mod fact;
pub mod layout;
pub mod project;

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::ConnectionFrameFileSliceFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        layout::decode_fact(fact.body())
    }
}
