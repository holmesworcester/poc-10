//! Encrypted connection-frame projection and envelope helpers.
//!
//! Connection frames bundle protocol facts after a connection has been
//! bootstrapped. Inbound network bytes are first classified by the receive
//! handler: bootstrap request/response bytes become their durable semantic
//! facts directly, while encrypted established-connection bytes become
//! ephemeral small or large connection-frame facts. This module owns the fixed
//! frame layout, sendability checks, decryption, and projection that turns an
//! opened frame into durable child facts plus `connection::fact_receipt`
//! records.

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
    Large(fact::ConnectionFrameLargeFact),
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<ProjectionPayload, String> {
    match bytes.first().copied() {
        Some(layout::TYPE_CONNECTION_FRAME_SMALL) => {
            layout::decode_small_fact(bytes).map(ProjectionPayload::Small)
        }
        Some(layout::TYPE_CONNECTION_FRAME_LARGE) => {
            layout::decode_large_fact(bytes).map(ProjectionPayload::Large)
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
