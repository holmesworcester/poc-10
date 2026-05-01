//! Apply-path maintenance hooks for the projected sync state.
//!
//! When a durable event is successfully applied inside the inbound chain,
//! several pieces of projected state must stay current:
//!
//! 1. `dep_cache` gains `(workspace_id, root_event_id, dep_event_id, depth)`
//!    rows for the transitive closure `D(r)` (plan.md lines 324-328).
//! 2. `negentropy_root_membership` gains `(workspace_id, node, event_id)`
//!    rows along the leaf-to-root path of the node tree, and
//!    `negentropy_dep_refcount` is bumped for declared deps that aren't
//!    themselves roots at that node (plan.md lines 343-364).
//! 3. Any node already requesting THIS event id as a dep flips its
//!    `present_locally` bit and folds the dep contribution into `dep_hash`.
//!
//! This module is the single seam the apply path uses to invoke all three.
//! It is called from `runtime::control_loop::inbound_step` after a durable
//! event reaches `EventStatus::Applied`, inside the same transaction as
//! the apply itself. Non-durable scopes (`Local`, `EndpointLocal`) MUST
//! NOT trigger maintenance — only durable rows are part of the durable
//! graph (plan.md lines 374-385).
//!
//! # `node_path` derivation choice
//!
//! The negentropy-tree node id space is opaque to this module — `update.rs`
//! just walks whatever node path the caller provides leaf-first. We pick a
//! deterministic path derived from the event id itself so:
//!
//!   - every endpoint computes the same path for the same event id
//!     (negentropy fingerprint comparisons require this),
//!   - the path is fully transparent to the caller (no extra state lookup),
//!   - the depth is fixed and small, bounding the per-apply work to O(D).
//!
//! Specifically: for `D = NODE_PATH_DEPTH` (default `4`) we generate
//! `D + 1` nodes:
//!
//! ```text
//!   level 0 (leaf):  id_prefix(event_id, 4)   // 4-byte prefix
//!   level 1:         id_prefix(event_id, 3)
//!   level 2:         id_prefix(event_id, 2)
//!   level 3:         id_prefix(event_id, 1)
//!   level 4 (root):  []                       // workspace-wide root
//! ```
//!
//! Each level's node id is the BLAKE3 event-id truncated to `(D - level)`
//! bytes; the root node is the empty-bytes sentinel meaning "the whole
//! workspace tree". Walked leaf → root, this matches the `update.rs`
//! convention.
//!
//! Why this shape:
//! - Trivially deterministic and reproducible across endpoints.
//! - 4 bytes of prefix = 2^32 possible leaves, more than enough for the
//!   per-workspace event volume we expect.
//! - Each level halves the populated set of nodes (assuming uniform
//!   BLAKE3 distribution), giving the negentropy compare a usable
//!   tree-of-fingerprints structure.
//! - The constant `NODE_PATH_DEPTH` is a knob: future range-tree shapes
//!   (e.g., a Merkle prefix tree with branching factor 16) can replace
//!   this without touching call sites — they all flow through
//!   `after_durable_apply`.
//!
//! TODO(plan.md follow-up): once the negentropy compare projector picks
//! a real branching factor + leaf-encoding scheme, swap `derive_node_path`
//! for the matching helper. The current shape is correct (deterministic,
//! O(D) work, leaves XOR-linked through ancestors) but is not yet
//! load-tested at scale.

use rusqlite::{params, Connection, OptionalExtension};

use crate::event_modules::{parse_event, ParsedEvent};
use crate::runtime::control_loop::work_item::{BlakeId, WorkspaceId};

use super::{dep_cache, negentropy_tree};

// NOTE: the legacy `event_workspace_map` lookup table that lived here was
// retired as part of plan.md stage 1 of dropping `recorded_by`. The
// (event_id -> workspace_id) mapping is now carried directly on
// `events_canonical.workspace_id`. The chain populates the column via
// `finalize_admitted` on the first transition out of `processing`, and
// callers that previously read `event_workspace_map` should call
// `crate::state::events_canonical::get_workspace_id` instead. See
// `lookup_event_workspace` below for the (deprecated) compatibility
// shim.

/// Branching depth of the synthetic node path used for negentropy-tree
/// maintenance. See module-level docs.
pub const NODE_PATH_DEPTH: usize = 4;

/// Build the `D + 1` node ids for `event_id`, leaf-first.
pub fn derive_node_path(event_id: &BlakeId) -> Vec<Vec<u8>> {
    let mut out = Vec::with_capacity(NODE_PATH_DEPTH + 1);
    // leaf at full depth, then progressively shorter prefixes, ending at
    // the empty-bytes workspace root.
    for level in 0..=NODE_PATH_DEPTH {
        let bytes_kept = NODE_PATH_DEPTH.saturating_sub(level);
        out.push(event_id[..bytes_kept].to_vec());
    }
    out
}

/// Look up the workspace id for an event by reading
/// `events_canonical.workspace_id` directly. Returns `Ok(None)` if the
/// row doesn't exist or hasn't been finalized yet (column still NULL).
///
/// Phase 1 of the `recorded_by` retirement (plan.md): this used to
/// consult a sibling `event_workspace_map` table. That table is gone;
/// `events_canonical.workspace_id` is the canonical source.
pub fn lookup_event_workspace(
    event_id: &BlakeId,
    db: &Connection,
) -> rusqlite::Result<Option<WorkspaceId>> {
    crate::state::events_canonical::get_workspace_id(db, event_id)
}

/// Resolve the declared dep ids of an event by reading its canonical bytes
/// from `events_canonical`, parsing through the registry, and reading the
/// `dep_field_values()` accessor.
///
/// Returns an empty Vec if the event is not yet in `events_canonical`
/// (which shouldn't happen for a row we just applied — but the helper is
/// defensive so it can be called from `dep_cache::compute_transitive` for
/// transitive lookups where the dep itself may not be locally present).
pub fn deps_of_event(event_id: &BlakeId, db: &Connection) -> rusqlite::Result<Vec<BlakeId>> {
    let bytes: Option<Vec<u8>> = db
        .query_row(
            "SELECT canonical_event_bytes FROM events_canonical WHERE event_id = ?1",
            params![event_id.to_vec()],
            |r| r.get(0),
        )
        .optional()?;
    let bytes = match bytes {
        Some(b) if !b.is_empty() => b,
        _ => return Ok(Vec::new()),
    };
    let parsed: ParsedEvent = match parse_event(&bytes) {
        Ok(p) => p,
        Err(_) => return Ok(Vec::new()),
    };
    Ok(parsed
        .dep_field_values()
        .into_iter()
        .map(|(_field, id)| id)
        .collect())
}

/// Wraps the `deps_of_event` lookup as the infallible-resolver shape that
/// `dep_cache::compute_transitive` expects.
#[derive(Debug)]
struct ResolveDepsErr(rusqlite::Error);
impl std::fmt::Display for ResolveDepsErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for ResolveDepsErr {}

/// Apply-path maintenance for a durable event that has just reached
/// `EventStatus::Applied`. Runs three steps inside the caller's
/// transaction:
///
/// 1. Compute the `node_path` for `event_id` via `derive_node_path`.
/// 2. Call `negentropy_tree::on_root_inserted` so the root membership
///    + dep refcount tables along the path are updated.
/// 3. Call `dep_cache::on_root_inserted` so the transitive closure
///    `D(event_id)` is written.
/// 4. Call `negentropy_tree::on_event_present` so any node previously
///    requesting `event_id` as a dep flips `present_locally` and folds
///    the contribution into `dep_hash`.
///
/// Errors are surfaced as `rusqlite::Error` so the caller's transaction
/// can roll back atomically.
pub fn after_durable_apply(
    workspace_id: &WorkspaceId,
    event_id: &BlakeId,
    db: &Connection,
) -> rusqlite::Result<()> {
    // Make sure all the projected-sync schemas are in place. Idempotent.
    negentropy_tree::ensure_schema(db)?;
    dep_cache::ensure_schema(db)?;

    // Resolve the event's *declared* (immediate) deps once — this is what
    // the negentropy-tree update needs. dep_cache walks the transitive
    // closure separately.
    let immediate_deps = deps_of_event(event_id, db)?;

    // 1+2. Walk the node path, adding root membership + dep requirements.
    let node_path = derive_node_path(event_id);
    negentropy_tree::on_root_inserted(workspace_id, event_id, &immediate_deps, &node_path, db)?;

    // 3. Compute and persist the transitive dep closure.
    dep_cache::on_root_inserted(
        workspace_id,
        event_id,
        |id| -> Result<Vec<BlakeId>, ResolveDepsErr> {
            deps_of_event(id, db).map_err(ResolveDepsErr)
        },
        db,
    )
    .map_err(|boxed| {
        // The dep_cache helper boxes its error. Downcast back to rusqlite
        // when we can; otherwise stuff it into a generic SQL error so the
        // caller sees a single error type.
        if let Some(inner) = boxed.downcast_ref::<ResolveDepsErr>() {
            rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("deps_of_event: {}", inner.0),
            )))
        } else {
            rusqlite::Error::ToSqlConversionFailure(Box::new(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("dep_cache::on_root_inserted: {}", boxed),
            )))
        }
    })?;

    // 4. Notify the negentropy tree that this event is now locally present.
    negentropy_tree::on_event_present(workspace_id, event_id, db)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_node_path_is_deterministic() {
        let id = [0xABu8; 32];
        let p1 = derive_node_path(&id);
        let p2 = derive_node_path(&id);
        assert_eq!(p1, p2);
        assert_eq!(p1.len(), NODE_PATH_DEPTH + 1);
        // leaf carries the most bytes, root carries none.
        assert_eq!(p1[0].len(), NODE_PATH_DEPTH);
        assert_eq!(p1[NODE_PATH_DEPTH].len(), 0);
    }

    #[test]
    fn derive_node_path_distinguishes_distinct_ids() {
        let a = [0x11u8; 32];
        let b = [0x22u8; 32];
        // Leaf nodes differ.
        assert_ne!(derive_node_path(&a)[0], derive_node_path(&b)[0]);
        // Root node is the same (workspace-wide).
        assert_eq!(
            derive_node_path(&a)[NODE_PATH_DEPTH],
            derive_node_path(&b)[NODE_PATH_DEPTH]
        );
    }
}
