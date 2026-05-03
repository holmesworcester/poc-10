pub mod dependent_event;

use crate::store::ProjectionOutput;

pub fn project_record(bytes: &[u8]) -> Result<Option<ProjectionOutput>, String> {
    match bytes.first().copied() {
        Some(
            dependent_event::codec::TYPE_DEPENDENT_EVENT
            | dependent_event::codec::TYPE_STAGED_DEPENDENT_EVENT,
        ) => Ok(Some(dependent_event::projector::project(bytes)?)),
        _ => Ok(None),
    }
}
