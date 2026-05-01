//! Registry adapter for `NeedEvent`.
//!
//! ### Pure-projector dispatch
//!
//! `project_pure` reads `ctx.local_sync_has_event` (populated by
//! `state::generic_context::populate_sync_context`), and emits:
//!
//! ```text
//! need.project:
//!   if local has event_id: outbox(connection_id, event_id)
//!   else: emit nothing
//! ```
//!
//! The outbox row carries the **durable** event_id; the per-connection
//! sender resolves canonical bytes and wraps at egress.
//!
//! The DB-aware `projector::project` function still exists for legacy
//! smoke-test use; the chain dispatches through this `project_pure`.

use super::codec::{encode, parse};
use super::event::{NeedEvent, NEED_TYPE_CODE};
use crate::event_modules::registry::{EventTypeMeta, ShareScope};
use crate::event_modules::{EventError, ParsedEvent};
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

fn parse_for_registry(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    parse(blob)
        .map(ParsedEvent::Need)
        .map_err(|_| EventError::InvalidMetadata("need wire decode failed"))
}

fn encode_for_registry(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let ev = match event {
        ParsedEvent::Need(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    Ok(encode(ev))
}

pub fn project_pure(
    _event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let ev: &NeedEvent = match parsed {
        ParsedEvent::Need(v) => v,
        _ => return ProjectorResult::reject("not a need event".to_string()),
    };

    if !ctx.local_sync_has_event.unwrap_or(false) {
        return ProjectorResult::valid(Vec::new());
    }

    let now_ms = ev.created_at_ms as i64;
    let ops = vec![WriteOp::InsertOrIgnore {
        table: "outbox",
        columns: vec!["connection_id", "event_id", "queued_at_ms"],
        values: vec![
            SqlVal::Blob(ev.connection_id.to_vec()),
            SqlVal::Blob(ev.event_id.to_vec()),
            SqlVal::Int(now_ms),
        ],
    }];
    ProjectorResult::valid(ops)
}

pub static NEED_META: EventTypeMeta = EventTypeMeta {
    type_code: NEED_TYPE_CODE,
    type_name: "need",
    projection_table: "sync_needs_seen",
    share_scope: ShareScope::Local,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_for_registry,
    encode: encode_for_registry,
    projector: project_pure,
    ensure_schema: Some(super::ensure_schema),
};
