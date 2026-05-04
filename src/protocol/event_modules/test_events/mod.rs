//! Test-only event modules.
//!
//! These modules exist to exercise protocol mechanics with real events. They
//! should stay honest: no fake harness writes, no bypassing the common worker,
//! and no assumptions that would not hold for a production event module.

pub mod event_with_deps;

use crate::protocol::event_modules::worker::ProjectionOutput;

pub fn project_record(bytes: &[u8]) -> Result<Option<ProjectionOutput>, String> {
    match bytes.first().copied() {
        Some(
            event_with_deps::codec::TYPE_EVENT_WITH_DEPS
            | event_with_deps::codec::TYPE_STAGED_EVENT_WITH_DEPS,
        ) => Ok(Some(event_with_deps::projector::project(bytes)?)),
        _ => Ok(None),
    }
}
