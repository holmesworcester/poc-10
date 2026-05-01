//! Registry adapter for `HaveEvent`.
//!
//! ### Pure-projector dispatch
//!
//! `project_pure` reads `ctx.local_sync_has_event`, populated by
//! `state::generic_context::populate_sync_context`, and emits:
//!
//! ```text
//! have.project:
//!   if local has event_id: emit nothing
//!   else: emit endpoint-local Need(event_id) + outbox row
//! ```
//!
//! The DB-aware `projector::project` function still exists for legacy
//! smoke-test use; the chain dispatches through this `project_pure`.

use super::codec::{encode, parse};
use super::event::{HaveEvent, HAVE_TYPE_CODE};
use crate::event_modules::registry::{EventTypeMeta, ShareScope};
use crate::event_modules::sync::need::{codec as need_codec, event::NeedEvent};
use crate::event_modules::{EventError, ParsedEvent};
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use crate::runtime::control_loop::work_item::BlakeId;
use crate::state::events_canonical::{EventScope, EventStatus};

fn parse_for_registry(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    parse(blob)
        .map(ParsedEvent::Have)
        .map_err(|_| EventError::InvalidMetadata("have wire decode failed"))
}

fn encode_for_registry(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let ev = match event {
        ParsedEvent::Have(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    Ok(encode(ev))
}

fn blake3_id(bytes: &[u8]) -> BlakeId {
    let h = blake3::hash(bytes);
    let mut id = [0u8; 32];
    id.copy_from_slice(h.as_bytes());
    id
}

pub fn project_pure(
    _event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let ev: &HaveEvent = match parsed {
        ParsedEvent::Have(v) => v,
        _ => return ProjectorResult::reject("not a have event".to_string()),
    };

    // Default to "we don't have it" if the loader didn't populate the
    // field (defensive; the loader populates it for every Have event).
    if ctx.local_sync_has_event.unwrap_or(false) {
        return ProjectorResult::valid(Vec::new());
    }

    // Synthesize an endpoint-local Need event and queue it for the connection.
    let need = NeedEvent {
        connection_id: ev.connection_id,
        workspace_id: ev.workspace_id,
        event_id: ev.event_id,
        created_at_ms: ev.created_at_ms,
    };
    let blob = need_codec::encode(&need);
    let need_id = blake3_id(&blob);
    let now_ms = ev.created_at_ms as i64;

    let ops = vec![
        WriteOp::InsertOrIgnore {
            table: "events_canonical",
            columns: vec![
                "event_id",
                "canonical_event_bytes",
                "workspace_id",
                "scope",
                "status",
                "created_at_ms",
            ],
            values: vec![
                SqlVal::Blob(need_id.to_vec()),
                SqlVal::Blob(blob),
                SqlVal::Blob(ev.workspace_id.to_vec()),
                SqlVal::Text(EventScope::EndpointLocal.as_str().to_string()),
                SqlVal::Text(EventStatus::Applied.as_str().to_string()),
                SqlVal::Int(now_ms),
            ],
        },
        WriteOp::InsertOrIgnore {
            table: "outbox",
            columns: vec!["connection_id", "event_id", "queued_at_ms"],
            values: vec![
                SqlVal::Blob(ev.connection_id.to_vec()),
                SqlVal::Blob(need_id.to_vec()),
                SqlVal::Int(now_ms),
            ],
        },
    ];
    ProjectorResult::valid(ops)
}

pub static HAVE_META: EventTypeMeta = EventTypeMeta {
    type_code: HAVE_TYPE_CODE,
    type_name: "have",
    projection_table: "sync_haves_seen",
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
