//! Registry adapter for `SyncWindowEvent`.
//!
//! Wire-only, like `negentropy`: no signature, no durable state. The pure
//! projector returns Valid with no `WriteOp`s.

use super::event::SYNC_WINDOW_TYPE_CODE;
use super::codec::{encode, parse};
use crate::event_modules::registry::{EventTypeMeta, ShareScope};
use crate::event_modules::{EventError, ParsedEvent};
use crate::projection::contract::{ContextSnapshot, ProjectorResult};

fn parse_for_registry(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    parse(blob)
        .map(ParsedEvent::SyncWindow)
        .map_err(|_| EventError::InvalidMetadata("sync_window wire decode failed"))
}

fn encode_for_registry(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let ev = match event {
        ParsedEvent::SyncWindow(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    Ok(encode(ev))
}

pub fn project_pure(
    _event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    if !matches!(parsed, ParsedEvent::SyncWindow(_)) {
        return ProjectorResult::reject("not a sync_window event".to_string());
    }
    // Wire-only: nothing to write.
    ProjectorResult::valid(Vec::new())
}

pub static SYNC_WINDOW_META: EventTypeMeta = EventTypeMeta {
    type_code: SYNC_WINDOW_TYPE_CODE,
    type_name: "sync_window",
    // TODO(plan.md cutover): no durable table — name retained for diagnostics.
    projection_table: "(none)",
    share_scope: ShareScope::Local,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_for_registry,
    encode: encode_for_registry,
    projector: project_pure,
    ensure_schema: None,
};
