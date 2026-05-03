pub mod content_event;

use crate::store::ProjectionOutput;

pub fn project_record(bytes: &[u8]) -> Result<Option<ProjectionOutput>, String> {
    match bytes.first().copied() {
        Some(content_event::codec::TYPE_CONTENT) => {
            Ok(Some(content_event::projector::project(bytes)?))
        }
        _ => Ok(None),
    }
}
