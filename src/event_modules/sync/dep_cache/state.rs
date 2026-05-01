//! Shared types for the dep cache.
//!
//! Right now this is just the public alias used by callers; the actual
//! per-row shape is captured by the SQL schema. This file exists so the
//! per-file event-module pattern (plan.md line 112) is followed even
//! when a module is small.

use crate::runtime::control_loop::work_item::BlakeId;

/// Returned by `compute_transitive` — `(dep_event_id, depth)`. Ordering is
/// BFS-discovery order (deterministic given the input graph).
pub type DepRow = (BlakeId, i32);
