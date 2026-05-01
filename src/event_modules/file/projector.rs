//! Pure projector for the `file` event (type 45).
//!
//! Plan.md Stage 2 chain-friendly contract:
//! - The event carries its own `workspace_id`; the projector reads it
//!   directly and writes `files.workspace_id` from the parsed event,
//!   not from the legacy `current_recorded_by()` thread-local.
//! - Label gates (plan.md §164-170): a `removed_by:*` label on the
//!   signer rejects projection.
//! - Per-slice integrity (bao verification) is done in the slice
//!   projector — the file projector only persists the descriptor.

use super::super::ParsedEvent;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

pub fn project_pure(
    event_id_b64: &str,
    parsed: &ParsedEvent,
    ctx: &ContextSnapshot,
) -> ProjectorResult {
    let f = match parsed {
        ParsedEvent::File(f) => f,
        _ => return ProjectorResult::reject("not a file event".to_string()),
    };

    if f.file_name.trim().is_empty() {
        return ProjectorResult::reject("file_name must not be empty".to_string());
    }
    if f.size_bytes > 0 && f.slice_count == 0 {
        return ProjectorResult::reject(
            "size_bytes > 0 but slice_count == 0".to_string(),
        );
    }

    // Plan.md Stage 3.5 step 5C: `recorded_by` shadow column dropped.
    // The projector no longer reads or writes it.
    let workspace_id_b64 = event_id_to_base64(&f.workspace_id);
    let signed_by_b64 = event_id_to_base64(&f.signed_by);

    // Label-based gate (plan.md §164-170): refuse to project if the signer
    // identity carries a `removed_by:*` label.
    let signer_removed = ctx
        .labels
        .get(&signed_by_b64)
        .map(|labels| labels.iter().any(|l| l.starts_with("removed_by:")))
        .unwrap_or(false);
    if signer_removed {
        return ProjectorResult::reject(
            "file signer identity has been removed (removed_by label)".to_string(),
        );
    }

    let ops = vec![WriteOp::InsertOrIgnore {
        table: "files",
        columns: vec![
            "workspace_id",
            "event_id",
            "file_name",
            "size_bytes",
            "slice_count",
            "bao_outboard",
            "content_hash",
            "created_at_ms",
        ],
        values: vec![
            SqlVal::Text(workspace_id_b64),
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Text(f.file_name.clone()),
            SqlVal::Int(f.size_bytes as i64),
            SqlVal::Int(f.slice_count as i64),
            SqlVal::Blob(f.bao_outboard.clone()),
            SqlVal::Blob(f.content_hash.to_vec()),
            SqlVal::Int(f.created_at_ms as i64),
        ],
    }];
    ProjectorResult::valid(ops)
}
