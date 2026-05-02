pub mod control_loop_tables;
pub mod daemon_identity;
pub mod event_display;
pub mod local_client_ops;
pub mod need_queue;
pub mod project_queue;
pub mod queue;
pub mod schema;
pub mod store;
pub mod timeline;
pub mod transport_creds;

use rusqlite::{Connection, Result as SqliteResult};
use std::path::Path;

/// Open database connection with WAL mode and performance pragmas
pub fn open_connection<P: AsRef<Path>>(path: P) -> SqliteResult<Connection> {
    let conn = Connection::open(path)?;
    apply_pragmas(&conn)?;
    Ok(conn)
}

/// Wrap a SQLite open error into a user-friendly message.
pub fn friendly_db_error<P: AsRef<Path>>(path: P, e: rusqlite::Error) -> String {
    let p = path.as_ref();
    match e {
        rusqlite::Error::SqliteFailure(ref err, _)
            if err.code == rusqlite::ffi::ErrorCode::CannotOpen =>
        {
            if let Some(parent) = p.parent() {
                if !parent.exists() {
                    return format!(
                        "cannot open database: directory does not exist: {}",
                        parent.display()
                    );
                }
            }
            format!("cannot open database: {}", p.display())
        }
        rusqlite::Error::SqliteFailure(ref err, ref msg) => {
            let detail = msg.as_deref().unwrap_or("unknown error");
            match err.code {
                rusqlite::ffi::ErrorCode::NotADatabase => {
                    format!(
                        "cannot open database: file is not a database: {}",
                        p.display()
                    )
                }
                rusqlite::ffi::ErrorCode::ReadOnly => {
                    format!("cannot open database: read-only: {}", p.display())
                }
                _ => format!("cannot open database: {} ({})", detail, p.display()),
            }
        }
        other => format!("cannot open database: {} ({})", other, p.display()),
    }
}

/// Open in-memory database (for testing)
#[cfg(test)]
pub fn open_in_memory() -> SqliteResult<Connection> {
    let conn = Connection::open_in_memory()?;
    apply_pragmas(&conn)?;
    Ok(conn)
}

fn apply_pragmas(conn: &Connection) -> SqliteResult<()> {
    if low_mem_mode() {
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA cache_size = -256;
            PRAGMA cache_spill = ON;
            PRAGMA temp_store = FILE;
            PRAGMA mmap_size = 0;
            PRAGMA wal_autocheckpoint = 64;
            PRAGMA journal_size_limit = 262144;
            PRAGMA soft_heap_limit = 2097152;
            PRAGMA busy_timeout = 5000;
            PRAGMA foreign_keys = OFF;
            ",
        )?;
    } else {
        conn.execute_batch(
            "
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA cache_size = -64000;
            PRAGMA busy_timeout = 5000;
            PRAGMA foreign_keys = OFF;
            PRAGMA temp_store = MEMORY;
            ",
        )?;
    }
    Ok(())
}

use crate::tuning::low_mem_mode;

pub fn ensure_infra_schema(conn: &Connection) -> SqliteResult<()> {
    // Boundary tables owned by `state` (substrate, not event-module-owned).
    // `plan.md` "State and Registry", lines 124-176: `events_canonical`,
    // `inbound_bytes`, `blocked_by_event`, `outbox`, `labels`,
    // `job_schedules`, `inbound_observations` live here.
    store::ensure_schema(conn)?;
    daemon_identity::ensure_schema(conn)?;
    event_display::ensure_schema(conn)?;
    project_queue::ensure_schema(conn)?;
    timeline::ensure_schema(conn)?;
    transport_creds::ensure_schema(conn)?;
    need_queue::ensure_schema(conn)?;
    local_client_ops::ensure_schema(conn)?;
    control_loop_tables::ensure_schema(conn)?;
    // Domain schema is registry-driven: walk every event module's
    // `EventTypeMeta::ensure_schema` so `state/db` does not centrally know
    // the domain shape. Each module declares its own tables.
    crate::event_modules::ensure_all_module_schemas(conn)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_in_memory() {
        let conn = open_in_memory().unwrap();
        let journal_mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        // In-memory databases may report "memory" instead of "wal"
        assert!(journal_mode == "wal" || journal_mode == "memory");
    }

    /// `ensure_infra_schema` walks the event-module registry and invokes
    /// every module's `ensure_schema`. After it completes, the
    /// representative per-module projection tables must be queryable —
    /// proving that `state/db` no longer hard-codes module-specific calls
    /// and that the registry-driven boot pass reaches every module
    /// (plan.md "State and Registry", lines 124-176).
    #[test]
    fn ensure_infra_schema_creates_all_module_tables() {
        let conn = open_in_memory().unwrap();
        ensure_infra_schema(&conn).unwrap();
        // Pick representative tables across the event-module families:
        //   - tenant -> tenants
        //   - message -> messages
        //   - peer_shared -> peers_shared
        //   - connection (top-level event) -> connections
        //   - connection_prekey (sub-event of the connection family)
        //     -> connection_prekeys
        //   - sync::compare (negentropy sync family) ->
        //     sync_compares_seen
        // Each is queried with an empty SELECT; if any table is missing
        // SQLite raises "no such table" and the test fails.
        for table in [
            "tenants",
            "messages",
            "peers_shared",
            "connections",
            "connection_prekeys",
            "sync_compares_seen",
        ] {
            let sql = format!("SELECT COUNT(*) FROM {}", table);
            let n: i64 = conn
                .query_row(&sql, [], |r| r.get(0))
                .unwrap_or_else(|e| panic!("table {} not queryable: {}", table, e));
            assert_eq!(n, 0, "fresh DB: {} should be empty", table);
        }
        // And the boundary tables (owned by state, not by any event
        // module) must also be present.
        for table in [
            "events_canonical",
            "inbound_bytes",
            "blocked_by_event",
            "outbox",
            "labels",
            "job_schedules",
            "inbound_observations",
        ] {
            let sql = format!("SELECT COUNT(*) FROM {}", table);
            let n: i64 = conn
                .query_row(&sql, [], |r| r.get(0))
                .unwrap_or_else(|e| panic!("boundary table {} not queryable: {}", table, e));
            assert_eq!(n, 0, "fresh DB: {} should be empty", table);
        }
    }
}
