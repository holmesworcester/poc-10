//! Pure projector for the `file_slice` event (type 46).
//!
//! Plan.md Stage 2 chain-friendly contract:
//! - The event carries its own `workspace_id`; the projector reads it
//!   directly and writes `file_slices.workspace_id` from the parsed
//!   event, not from the legacy `current_recorded_by()` thread-local.
//! - Per-slice integrity is checked here: `blake3(slice_bytes) == slice_hash`.
//!   This makes slices fully self-validating in the chain — no
//!   cross-event context lookup required ("slices work like every
//!   other event"). Whole-file integrity is still verifiable at
//!   save time using the parent file's `bao_outboard` + `content_hash`.
//! - Label gates (plan.md §164-170): `removed_by:*` on the signer
//!   rejects projection.

use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

pub fn project_pure(
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let s = match parsed {
        ParsedEvent::FileSlice(s) => s,
        _ => return ProjectorResult::reject("not a file_slice event".to_string()),
    };

    // Per-slice integrity check: blake3(slice_bytes) must equal the
    // declared slice_hash. This is the bao-tree leaf check in
    // self-validating form — no descriptor lookup needed.
    let actual_hash = blake3::hash(&s.slice_bytes);
    if actual_hash.as_bytes() != &s.slice_hash {
        return ProjectorResult::reject(format!(
            "file_slice hash mismatch at index {}",
            s.slice_index
        ));
    }

    // Plan.md Stage 3.5 step 5C: `recorded_by` shadow column dropped.
    // The projector no longer reads or writes it.
    let workspace_id_b64 = event_id_to_base64(&s.workspace_id);
    let file_event_id_b64 = event_id_to_base64(&s.file_event_id);
    let signed_by_b64 = event_id_to_base64(&s.signed_by);

    // Label-based gate: refuse to project if the signer identity
    // carries a `removed_by:*` label.
    let signer_removed = ctx
        .labels
        .get(&signed_by_b64)
        .map(|labels| labels.iter().any(|l| l.starts_with("removed_by:")))
        .unwrap_or(false);
    if signer_removed {
        return ProjectorResult::reject(
            "file_slice signer identity has been removed (removed_by label)".to_string(),
        );
    }

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "file_slices",
        columns: vec![
            "workspace_id",
            "event_id",
            "file_event_id",
            "slice_index",
            "slice_hash",
            "slice_bytes",
            "created_at_ms",
        ],
        values: vec![
            SqlVal::Text(workspace_id_b64),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(file_event_id_b64),
            SqlVal::Int(s.slice_index as i64),
            SqlVal::Blob(s.slice_hash.to_vec()),
            SqlVal::Blob(s.slice_bytes.clone()),
            SqlVal::Int(s.created_at_ms as i64),
        ],
    }];
    ProjectorResult::valid(ops)
}
