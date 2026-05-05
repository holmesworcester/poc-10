//! Identity domain.
//!
//! Identity owns shared workspace roots plus local endpoint material and invite
//! secrets. Local facts let this node create bootstrap traffic and decide
//! whether an incoming request is authorized, but they are not shared content
//! history.

pub mod device_invite;
pub mod endpoint;
pub mod endpoint_shared;
pub mod invite;
pub mod signed;
pub mod user;
pub mod user_invite;
pub mod workspace;

use crate::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

pub fn project_record(event: &EventWithContext<'_>) -> Result<Option<ProjectionOutput>, String> {
    let bytes = &event.record.canonical_bytes;
    match bytes.first().copied() {
        Some(device_invite::codec::TYPE_DEVICE_INVITE) => {
            Ok(Some(device_invite::projector::project(event)?))
        }
        Some(endpoint::codec::TYPE_LOCAL_ENDPOINT) => {
            Ok(Some(endpoint::projector::project(bytes)?))
        }
        Some(signed::codec::TYPE_SIGNED) => project_signed_record(event),
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

fn project_signed_record(event: &EventWithContext<'_>) -> Result<Option<ProjectionOutput>, String> {
    let envelope = signed::codec::decode(&event.record.canonical_bytes)?;
    match envelope.inner_type {
        endpoint_shared::codec::TYPE_ENDPOINT_SHARED => Ok(Some(
            endpoint_shared::projector::project_signed(&envelope, event)?,
        )),
        _ => Err(format!(
            "signed envelope inner type {} has no identity projector",
            envelope.inner_type
        )),
    }
}
