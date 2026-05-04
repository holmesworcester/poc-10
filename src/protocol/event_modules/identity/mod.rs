pub mod endpoint;
pub mod invite;

use crate::core::store::ProjectionOutput;

pub fn project_record(bytes: &[u8]) -> Result<Option<ProjectionOutput>, String> {
    match bytes.first().copied() {
        Some(endpoint::codec::TYPE_LOCAL_ENDPOINT) => {
            Ok(Some(endpoint::projector::project(bytes)?))
        }
        Some(invite::codec::TYPE_INVITE_SECRET) => Ok(Some(invite::projector::project(bytes)?)),
        _ => Ok(None),
    }
}
