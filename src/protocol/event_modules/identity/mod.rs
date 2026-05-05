//! Identity domain.
//!
//! Identity owns shared workspace roots plus local endpoint material and invite
//! secrets. Local facts let this node create bootstrap traffic and decide
//! whether an incoming request is authorized, but they are not shared content
//! history.

pub mod endpoint;
pub mod invite;
pub mod workspace;

use crate::protocol::event_modules::worker::ProjectionOutput;

pub fn project_record(bytes: &[u8]) -> Result<Option<ProjectionOutput>, String> {
    match bytes.first().copied() {
        Some(endpoint::codec::TYPE_LOCAL_ENDPOINT) => {
            Ok(Some(endpoint::projector::project(bytes)?))
        }
        Some(invite::codec::TYPE_INVITE_SECRET) => Ok(Some(invite::projector::project(bytes)?)),
        Some(workspace::codec::TYPE_WORKSPACE) => Ok(Some(workspace::projector::project(bytes)?)),
        _ => Ok(None),
    }
}
