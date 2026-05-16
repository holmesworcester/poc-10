//! Identity domain.
//!
//! Identity owns shared workspace roots plus local endpoint material,
//! invite-secret material, and invite-acceptance provenance. Local facts let this
//! node create connection bootstrap requests and remember why it accepted an
//! invite, but they are not shared content history or membership grants.

pub mod admin;
pub mod command_line;
pub mod device_invite;
pub mod endpoint;
pub mod endpoint_shared;
pub mod invite;
pub mod invite_accepted;
pub mod invite_server;
pub mod signed;
pub mod user;
pub mod user_invite;
pub mod workspace;

use crate::legacy::protocol::event_modules::types::EventRecord;
use crate::legacy::protocol::event_modules::worker::{EventWithContext, ProjectionOutput};

#[cfg(test)]
mod cli_tests;

pub fn project_record(event: &EventWithContext<'_>) -> Result<Option<ProjectionOutput>, String> {
    let bytes = &event.record.canonical_bytes;
    match bytes.first().copied() {
        Some(admin::layout::TYPE_ADMIN) => Ok(Some(admin::projector::project(event)?)),
        Some(device_invite::layout::TYPE_DEVICE_INVITE) => {
            Ok(Some(device_invite::projector::project(event)?))
        }
        Some(endpoint::layout::TYPE_LOCAL_ENDPOINT) => {
            Ok(Some(endpoint::projector::project(bytes)?))
        }
        Some(signed::layout::TYPE_SIGNED) => project_signed_record(event),
        Some(invite::layout::TYPE_INVITE_SECRET) => Ok(Some(invite::projector::project(bytes)?)),
        Some(invite_accepted::layout::TYPE_INVITE_ACCEPTED) => {
            Ok(Some(invite_accepted::projector::project(event)?))
        }
        Some(workspace::layout::TYPE_WORKSPACE) => Ok(Some(workspace::projector::project(bytes)?)),
        _ => Ok(None),
    }
}

fn project_signed_record(event: &EventWithContext<'_>) -> Result<Option<ProjectionOutput>, String> {
    let envelope = signed::layout::decode(&event.record.canonical_bytes)?;
    match envelope.inner_type {
        admin::layout::TYPE_ADMIN => Ok(Some(admin::projector::project_signed(&envelope, event)?)),
        device_invite::layout::TYPE_DEVICE_INVITE => Ok(Some(
            device_invite::projector::project_signed(&envelope, event)?,
        )),
        endpoint_shared::layout::TYPE_ENDPOINT_SHARED => Ok(Some(
            endpoint_shared::projector::project_signed(&envelope, event)?,
        )),
        invite_server::layout::TYPE_INVITE_SERVER => {
            Ok(Some(invite_server::projector::project(event)?))
        }
        user_invite::layout::TYPE_USER_INVITE => Ok(Some(user_invite::projector::project(event)?)),
        user::layout::TYPE_USER => Ok(Some(user::projector::project(event)?)),
        _ => Err(format!(
            "signed envelope inner type {} has no identity projector",
            envelope.inner_type
        )),
    }
}

pub fn signed_record_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let envelope = signed::layout::decode(&bytes)?;
    match envelope.inner_type {
        admin::layout::TYPE_ADMIN
        | endpoint_shared::layout::TYPE_ENDPOINT_SHARED
        | invite_server::layout::TYPE_INVITE_SERVER
        | user_invite::layout::TYPE_USER_INVITE
        | user::layout::TYPE_USER => signed::layout::record_from_bytes(bytes),
        device_invite::layout::TYPE_DEVICE_INVITE => {
            device_invite::layout::record_from_signed_bytes(bytes)
        }
        _ => Err(format!(
            "signed envelope inner type {} has no identity record",
            envelope.inner_type
        )),
    }
}

/// Tags owned by this domain. Used by the top-level dispatcher to route
/// ordinary tag-leading event bytes to `event_from_bytes`.
pub fn is_identity_tag(tag: u8) -> bool {
    matches!(
        tag,
        admin::layout::TYPE_ADMIN
            | device_invite::layout::TYPE_DEVICE_INVITE
            | endpoint::layout::TYPE_LOCAL_ENDPOINT
            | signed::layout::TYPE_SIGNED
            | invite::layout::TYPE_INVITE_SECRET
            | invite_accepted::layout::TYPE_INVITE_ACCEPTED
            | workspace::layout::TYPE_WORKSPACE
    )
}

/// Decode a tag-leading identity event into an `EventRecord`. Inner-only
/// types (admin/device_invite) are rejected: they must be wrapped in a
/// `signed` envelope to admit.
pub fn event_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let tag = bytes
        .first()
        .ok_or_else(|| "empty identity event bytes".to_string())?;
    match *tag {
        admin::layout::TYPE_ADMIN => Err("admin must be signed".to_string()),
        device_invite::layout::TYPE_DEVICE_INVITE => {
            Err("device_invite must be signed".to_string())
        }
        endpoint::layout::TYPE_LOCAL_ENDPOINT => endpoint::layout::record_from_bytes(bytes),
        signed::layout::TYPE_SIGNED => signed_record_from_bytes(bytes),
        invite::layout::TYPE_INVITE_SECRET => invite::layout::record_from_bytes(bytes),
        invite_accepted::layout::TYPE_INVITE_ACCEPTED => {
            invite_accepted::layout::record_from_bytes(bytes)
        }
        workspace::layout::TYPE_WORKSPACE => workspace::layout::record_from_bytes(bytes),
        other => Err(format!("unknown identity event type {other}")),
    }
}
