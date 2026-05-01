//! SQL schema for the projected transitive-dep cache.
//!
//! `dep_cache(workspace_id, root_event_id, dep_event_id, depth)` flattens
//! the transitive dependency closure `D(r)`. `depth` is the shortest hop
//! count from root to dep (useful diagnostically; the cache is otherwise
//! a set).

use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS dep_cache (
            workspace_id   BLOB NOT NULL,
            root_event_id  BLOB NOT NULL,
            dep_event_id   BLOB NOT NULL,
            depth          INTEGER NOT NULL,
            PRIMARY KEY (workspace_id, root_event_id, dep_event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_dep_cache_root
            ON dep_cache (workspace_id, root_event_id);
        ",
    )?;
    Ok(())
}
