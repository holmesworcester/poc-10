//! Content domain.
//!
//! Content events are the simplest shared events in this POC: timestamped bytes
//! with no dependencies and no projection rows. Their value is mostly as real
//! payload for sync and throughput tests, which makes their codec and command
//! path a useful baseline for more complex event modules.

pub mod cli;
pub mod content_event;

use crate::protocol::event_modules::worker::ProjectionOutput;

pub fn project_record(bytes: &[u8]) -> Result<Option<ProjectionOutput>, String> {
    match bytes.first().copied() {
        Some(content_event::codec::TYPE_CONTENT) => {
            Ok(Some(content_event::projector::project(bytes)?))
        }
        _ => Ok(None),
    }
}
