//! Content domain.
//!
//! Content events are signed workspace-scoped payload events. Their value is
//! mostly as real payload for sync and throughput tests, but they still follow
//! the shared-event auth rule: projection only accepts bytes signed by an
//! endpoint membership for the same workspace.

pub mod content_event;

use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

pub fn project_record(event: &EventWithContext<'_>) -> Result<Option<ProjectionOutput>, String> {
    let bytes = &event.record.canonical_bytes;
    match bytes.first().copied() {
        Some(content_event::codec::TYPE_SIGNED_CONTENT) => {
            content_event::codec::decode_signed(bytes)?;
            Ok(Some(content_event::projector::project(event)?))
        }
        _ => Ok(None),
    }
}
