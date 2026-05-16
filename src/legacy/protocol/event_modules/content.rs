//! Content domain.
//!
//! Content events are signed workspace-scoped payload events. Each leaf module
//! owns its own outer signed-envelope tag plus an inner content tag, and
//! projection enforces the shared-event auth rule: signers must be endpoint
//! memberships in the workspace.

pub mod command_line;
pub mod content_event;
pub mod file;
pub mod file_deletion;
pub mod file_slice;
pub mod message;
pub mod message_deletion;
pub mod reaction;

use crate::core::store::Store;
use crate::legacy::protocol::event_modules::types::EventRecord;
use crate::legacy::protocol::event_modules::worker::{
    AdmitDecision, EventWithContext, ProjectionOutput,
};

pub fn project_record(event: &EventWithContext<'_>) -> Result<Option<ProjectionOutput>, String> {
    let bytes = &event.record.canonical_bytes;
    match bytes.first().copied() {
        Some(content_event::layout::TYPE_SIGNED_CONTENT) => {
            Ok(Some(content_event::projector::project(event)?))
        }
        Some(message::layout::TYPE_SIGNED_MESSAGE) => Ok(Some(message::projector::project(event)?)),
        Some(reaction::layout::TYPE_SIGNED_REACTION) => {
            Ok(Some(reaction::projector::project(event)?))
        }
        Some(message_deletion::layout::TYPE_SIGNED_MESSAGE_DELETION) => {
            Ok(Some(message_deletion::projector::project(event)?))
        }
        Some(file::layout::TYPE_SIGNED_FILE) => Ok(Some(file::projector::project(event)?)),
        Some(file_slice::layout::TYPE_SIGNED_FILE_SLICE) => {
            Ok(Some(file_slice::projector::project(event)?))
        }
        Some(file_deletion::layout::TYPE_SIGNED_FILE_DELETION) => {
            Ok(Some(file_deletion::projector::project(event)?))
        }
        _ => Ok(None),
    }
}

/// Receive-side admission gate for content events. Dispatches by tag to the
/// leaf module's rows-owned `admit_check_received`, which decides whether
/// to admit, drop silently, or drop with a tombstone-row write. Schema is
/// the right home for the gate because it already owns the storage helpers
/// (tombstone existence checks, tombstone row construction) the gate
/// consults.
pub fn admit_check_received(store: &Store, record: &EventRecord) -> Result<AdmitDecision, String> {
    let bytes = &record.canonical_bytes;
    match bytes.first().copied() {
        Some(message::layout::TYPE_SIGNED_MESSAGE) => {
            message::rows::admit_check_received(store, bytes)
        }
        Some(reaction::layout::TYPE_SIGNED_REACTION) => {
            reaction::rows::admit_check_received(store, bytes)
        }
        Some(file::layout::TYPE_SIGNED_FILE) => file::rows::admit_check_received(store, bytes),
        Some(file_slice::layout::TYPE_SIGNED_FILE_SLICE) => {
            file_slice::rows::admit_check_received(store, bytes)
        }
        _ => Ok(AdmitDecision::Admit),
    }
}

/// Tags owned by this domain. Used by the top-level dispatcher to route
/// ordinary tag-leading event bytes to `event_from_bytes`.
pub fn is_content_tag(tag: u8) -> bool {
    matches!(
        tag,
        content_event::layout::TYPE_CONTENT
            | content_event::layout::TYPE_SIGNED_CONTENT
            | message::layout::TYPE_MESSAGE
            | message::layout::TYPE_SIGNED_MESSAGE
            | reaction::layout::TYPE_REACTION
            | reaction::layout::TYPE_SIGNED_REACTION
            | message_deletion::layout::TYPE_MESSAGE_DELETION
            | message_deletion::layout::TYPE_SIGNED_MESSAGE_DELETION
            | file::layout::TYPE_FILE
            | file::layout::TYPE_SIGNED_FILE
            | file_slice::layout::TYPE_FILE_SLICE
            | file_slice::layout::TYPE_SIGNED_FILE_SLICE
            | file_deletion::layout::TYPE_FILE_DELETION
            | file_deletion::layout::TYPE_SIGNED_FILE_DELETION
    )
}

/// Decode a tag-leading content event into an `EventRecord`. Unsigned
/// content tags are rejected: every content event must arrive in its signed
/// envelope form.
pub fn event_from_bytes(bytes: Vec<u8>) -> Result<EventRecord, String> {
    let tag = bytes
        .first()
        .ok_or_else(|| "empty content event bytes".to_string())?;
    match *tag {
        content_event::layout::TYPE_CONTENT => Err("content must be signed".to_string()),
        content_event::layout::TYPE_SIGNED_CONTENT => {
            content_event::layout::signed_record_from_bytes(bytes)
        }
        message::layout::TYPE_MESSAGE => Err("message must be signed".to_string()),
        message::layout::TYPE_SIGNED_MESSAGE => message::layout::signed_record_from_bytes(bytes),
        reaction::layout::TYPE_REACTION => Err("reaction must be signed".to_string()),
        reaction::layout::TYPE_SIGNED_REACTION => reaction::layout::signed_record_from_bytes(bytes),
        message_deletion::layout::TYPE_MESSAGE_DELETION => {
            Err("message deletion must be signed".to_string())
        }
        message_deletion::layout::TYPE_SIGNED_MESSAGE_DELETION => {
            message_deletion::layout::signed_record_from_bytes(bytes)
        }
        file::layout::TYPE_FILE => Err("file must be signed".to_string()),
        file::layout::TYPE_SIGNED_FILE => file::layout::signed_record_from_bytes(bytes),
        file_slice::layout::TYPE_FILE_SLICE => Err("file slice must be signed".to_string()),
        file_slice::layout::TYPE_SIGNED_FILE_SLICE => {
            file_slice::layout::signed_record_from_bytes(bytes)
        }
        file_deletion::layout::TYPE_FILE_DELETION => {
            Err("file deletion must be signed".to_string())
        }
        file_deletion::layout::TYPE_SIGNED_FILE_DELETION => {
            file_deletion::layout::signed_record_from_bytes(bytes)
        }
        other => Err(format!("unknown content event type {other}")),
    }
}
