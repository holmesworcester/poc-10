//! Established connection-frame family.
//!
//! Connection frames are encrypted carriers used after a `connection::response`
//! has materialized local connection context. The receive handler classifies
//! raw network bytes into ephemeral small, file-slice, or bundle frame facts;
//! the projector opens those bytes with the connection secret and emits durable
//! child facts plus `connection::fact_receipt` records.
//!
//! This family owns frame fact tags, fixed outer layout, sendability checks,
//! sealing/opening helpers, and frame projection. Core owns socket IO, and the
//! child fact families own semantic validation of the facts opened from a
//! frame.

pub mod create;
pub mod fact;
pub mod layout;
pub mod project;

pub use crate::core::wire::FixedLayout as ConnectionFrameDecode;
pub use create as receive;
pub use layout as frame;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectionPayload {
    Small(fact::ConnectionFrameSmallFact),
    FileSlice(fact::ConnectionFrameFileSliceFact),
    Bundle(fact::ConnectionFrameBundleFact),
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<ProjectionPayload, String> {
    match bytes.first().copied() {
        Some(layout::TYPE_CONNECTION_FRAME_SMALL) => {
            layout::decode_small_fact(bytes).map(ProjectionPayload::Small)
        }
        Some(layout::TYPE_CONNECTION_FRAME_FILE_SLICE) => {
            layout::decode_file_slice_fact(bytes).map(ProjectionPayload::FileSlice)
        }
        Some(layout::TYPE_CONNECTION_FRAME_BUNDLE) => {
            layout::decode_bundle_fact(bytes).map(ProjectionPayload::Bundle)
        }
        Some(other) => Err(format!("unknown connection_frame fact tag {other}")),
        None => Err("empty connection_frame fact".to_string()),
    }
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = ProjectionPayload;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
