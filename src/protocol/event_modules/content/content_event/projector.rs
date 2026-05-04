//! Projector for content events.
//!
//! Content has no read model yet. Projection validates the bytes and returns no
//! rows, which is still important: it proves the common worker can apply shared
//! events whose only durable representation is the event row itself.

use crate::protocol::event_modules::worker::ProjectionOutput;

use super::codec;

pub fn project(bytes: &[u8]) -> Result<ProjectionOutput, String> {
    codec::validate(bytes)?;
    Ok(ProjectionOutput::default())
}
