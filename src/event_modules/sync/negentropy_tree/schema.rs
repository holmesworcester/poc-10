//! SQL schema for the projected negentropy tree state.
//!
//! Tables:
//! - `negentropy_root_membership` — which root event ids are inside which
//!   range-tree node identifier (`R_v`).
//! - `negentropy_dep_refcount`    — per-(node, dep) refcount + presence flag,
//!   making 0→1 / 1→0 transitions explicit so dep_hash stays well-defined
//!   under duplicate edges.
//! - `negentropy_node_hash`        — domain-separated XOR hashes per node:
//!   `root_hash` over `Hset("root", R_v)` and `dep_hash` over
//!   `Hset("dep", X_v ∩ P)`. Combine into the per-node fingerprint
//!   `F_v` via `query::node_fingerprint`.

use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS negentropy_root_membership (
            workspace_id BLOB NOT NULL,
            node_id      BLOB NOT NULL,
            event_id     BLOB NOT NULL,
            PRIMARY KEY (workspace_id, node_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_negentropy_root_membership_event
            ON negentropy_root_membership (workspace_id, event_id);
        -- Workspace-agnostic event_id lookup. `local_has_event` in
        -- update.rs probes presence by event_id alone (it has no
        -- workspace context yet), and the existing
        -- `idx_negentropy_root_membership_event` is keyed
        -- `(workspace_id, event_id)` so the workspace-less query
        -- degrades to a full COVERING-INDEX scan. With 50 k+ rows that
        -- scan is a per-event O(N) hot spot in apply_sync_maintenance.
        CREATE INDEX IF NOT EXISTS idx_negentropy_root_membership_event_only
            ON negentropy_root_membership (event_id);

        CREATE TABLE IF NOT EXISTS negentropy_dep_refcount (
            workspace_id     BLOB NOT NULL,
            node_id          BLOB NOT NULL,
            dep_event_id     BLOB NOT NULL,
            refcount         INTEGER NOT NULL,
            present_locally  INTEGER NOT NULL,
            PRIMARY KEY (workspace_id, node_id, dep_event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_negentropy_dep_refcount_event
            ON negentropy_dep_refcount (workspace_id, dep_event_id);

        CREATE TABLE IF NOT EXISTS negentropy_node_hash (
            workspace_id BLOB NOT NULL,
            node_id      BLOB NOT NULL,
            root_hash    BLOB NOT NULL,
            dep_hash     BLOB NOT NULL,
            PRIMARY KEY (workspace_id, node_id)
        );
        ",
    )?;
    Ok(())
}
