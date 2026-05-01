//! `sync::dep_cache`: flattened transitive dependency closure `D(r)` per
//! root event (plan.md lines 324-328).
//!
//! `D(r) = transitive event ids required by r`. Maintained as projected
//! state so the dep-aware negentropy fold doesn't have to walk the
//! dependency graph during every compare.
//!
//! Single table `dep_cache(workspace_id, root_event_id, dep_event_id,
//! depth)` flattens the closure with the discovered depth (1 = direct,
//! 2 = via one hop, …). Computed on root insert via
//! `compute::compute_transitive` and written via `compute::on_root_inserted`.

pub mod compute;
pub mod schema;
pub mod state;

pub use compute::{compute_transitive, on_root_inserted};

use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    schema::ensure_schema(conn)
}
