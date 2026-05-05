//! Identity domain.
//!
//! Identity owns shared workspace roots plus local endpoint material and invite
//! secrets. Local facts let this node create bootstrap traffic and decide
//! whether an incoming request is authorized, but they are not shared content
//! history.

pub mod endpoint;
pub mod invite;
pub mod signed;
pub mod user;
pub mod user_invite;
pub mod workspace;

use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

pub fn project_record(event: &EventWithContext<'_>) -> Result<Option<ProjectionOutput>, String> {
    let bytes = &event.record.canonical_bytes;
    match bytes.first().copied() {
        Some(endpoint::codec::TYPE_LOCAL_ENDPOINT) => {
            Ok(Some(endpoint::projector::project(bytes)?))
        }
        Some(invite::codec::TYPE_INVITE_SECRET) => Ok(Some(invite::projector::project(bytes)?)),
        Some(signed::codec::TYPE_SIGNED) => {
            let envelope = signed::codec::decode(bytes)?;
            match envelope.inner_type {
                user_invite::codec::TYPE_USER_INVITE => {
                    Ok(Some(user_invite::projector::project(event)?))
                }
                user::codec::TYPE_USER => Ok(Some(user::projector::project(event)?)),
                other => Err(format!("unknown signed identity event type {other}")),
            }
        }
        Some(workspace::codec::TYPE_WORKSPACE) => Ok(Some(workspace::projector::project(bytes)?)),
        _ => Ok(None),
    }
}
