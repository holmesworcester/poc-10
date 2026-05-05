//! Content domain.
//!
//! Content events are the simplest shared events in this POC: timestamped bytes
//! with no dependencies and no projection rows. Their value is mostly as real
//! payload for sync and throughput tests, which makes their codec and command
//! path a useful baseline for more complex event modules.

pub mod content_event;

use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

pub fn project_record(event: &EventWithContext<'_>) -> Result<Option<ProjectionOutput>, String> {
    let bytes = &event.record.canonical_bytes;
    match bytes.first().copied() {
        Some(content_event::codec::TYPE_CONTENT) => {
            content_event::codec::validate(bytes)?;
            Ok(Some(content_event::projector::project(event)?))
        }
        _ => Ok(None),
    }
}
