//! Registry adapter for `CompareEvent`.
//!
//! ### Pure-projector dispatch
//!
//! `project_pure` reads the sync-extension fields populated by
//! `state::generic_context::populate_sync_context` (the local fingerprint
//! `F_v`, the child node-id set, and the leaf member set `R_v`) and emits
//! the recursive-fold WriteOps deterministically — no DB access, all the
//! state arrives via `ContextSnapshot`.
//!
//! Per plan.md lines 308-316:
//!
//! ```text
//! compare.project:
//!   if remote_fingerprint == F_v:
//!     emit nothing
//!   else if v is splittable:
//!     create endpoint-local compare events for each child and queue them in outbox
//!   else:
//!     create endpoint-local have-id events for the ids in R_v and queue them in outbox
//! ```
//!
//! The DB-aware `projector::project` function still exists for legacy
//! smoke-test use; the chain dispatches through this `project_pure`.

use super::codec::{encode, parse};
use super::event::{CompareEvent, COMPARE_TYPE_CODE};
use crate::event_modules::registry::{EventTypeMeta, ShareScope};
use crate::event_modules::sync::have::{codec as have_codec, event::HaveEvent};
use crate::event_modules::{EventError, ParsedEvent};
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use crate::runtime::control_loop::work_item::BlakeId;
use crate::state::events_canonical::{EventScope, EventStatus};

fn parse_for_registry(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    parse(blob)
        .map(ParsedEvent::Compare)
        .map_err(|_| EventError::InvalidMetadata("compare wire decode failed"))
}

fn encode_for_registry(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let ev = match event {
        ParsedEvent::Compare(v) => v,
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

/// Build the `(events_canonical row, outbox row)` write pair for a freshly
/// synthesized endpoint-local event, given its already-encoded canonical
/// bytes. Returns the event_id so callers can chain.
fn upsert_endpoint_local_event_ops(
    canonical_bytes: Vec<u8>,
    connection_id: &BlakeId,
    workspace_id: &BlakeId,
    created_at_ms: i64,
) -> (BlakeId, [WriteOp; 2]) {
    let event_id = blake3_id(&canonical_bytes);
    let ec = WriteOp::InsertOrIgnore {
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
            SqlVal::Blob(event_id.to_vec()),
            SqlVal::Blob(canonical_bytes),
            SqlVal::Blob(workspace_id.to_vec()),
            SqlVal::Text(EventScope::EndpointLocal.as_str().to_string()),
            SqlVal::Text(EventStatus::Applied.as_str().to_string()),
            SqlVal::Int(created_at_ms),
        ],
    };
    let ob = WriteOp::InsertOrIgnore {
        table: "outbox",
        columns: vec!["connection_id", "event_id", "queued_at_ms"],
        values: vec![
            SqlVal::Blob(connection_id.to_vec()),
            SqlVal::Blob(event_id.to_vec()),
            SqlVal::Int(created_at_ms),
        ],
    };
    (event_id, [ec, ob])
}

/// Pure projector: reads local sync state via `ContextSnapshot` and emits
/// the recursive-fold WriteOps. No DB access.
pub fn project_pure(
    _event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let ev: &CompareEvent = match parsed {
        ParsedEvent::Compare(v) => v,
        _ => return ProjectorResult::reject("not a compare event".to_string()),
    };

    // F_v == remote? -> emit nothing. Missing fingerprint snapshot is
    // treated as the all-zero fingerprint (no membership rows yet).
    let local_fp = ctx.local_sync_node_fingerprint.unwrap_or([0u8; 32]);
    if local_fp == ev.fingerprint {
        return ProjectorResult::valid(Vec::new());
    }

    let now_ms = ev.created_at_ms as i64;
    let mut ops: Vec<WriteOp> = Vec::new();

    // Splittable? Children populated by the loader from
    // negentropy_root_membership rows, each paired with the child's local
    // fingerprint `F_child`.
    if !ctx.local_sync_node_children.is_empty() {
        for (child_path, child_fp) in &ctx.local_sync_node_children {
            let child_ev = CompareEvent {
                connection_id: ev.connection_id,
                workspace_id: ev.workspace_id,
                node_id: child_path.clone(),
                fingerprint: *child_fp,
                created_at_ms: ev.created_at_ms,
            };
            let blob = super::codec::encode(&child_ev);
            let (_id, pair) = upsert_endpoint_local_event_ops(
                blob,
                &ev.connection_id,
                &ev.workspace_id,
                now_ms,
            );
            ops.extend(pair);
        }
        return ProjectorResult::valid(ops);
    }

    // Leaf: emit one Have(event_id) per id in R_v.
    for member in &ctx.local_sync_node_members {
        let have = HaveEvent {
            connection_id: ev.connection_id,
            workspace_id: ev.workspace_id,
            event_id: *member,
            created_at_ms: ev.created_at_ms,
        };
        let blob = have_codec::encode(&have);
        let (_id, pair) = upsert_endpoint_local_event_ops(
            blob,
            &ev.connection_id,
            &ev.workspace_id,
            now_ms,
        );
        ops.extend(pair);
    }
    ProjectorResult::valid(ops)
}

pub static COMPARE_META: EventTypeMeta = EventTypeMeta {
    type_code: COMPARE_TYPE_CODE,
    type_name: "compare",
    projection_table: "sync_compares_seen",
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
