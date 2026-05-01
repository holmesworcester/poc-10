//! `file` event (type 45): metadata record for a file — its name, total size,
//! slice count, content hash (blake3 root over the file plaintext), and the
//! bao outboard tree used to verify slices and assembled output.
//!
//! The actual bytes live in `file_slice` events (type 46); slices link back to
//! a file via the file event's id (`file_event_id`).
//!
//! Wave 1 trim: ported from poc-7 with the chain-friendly contract — directory
//! layout (codec.rs / projector.rs / queries.rs / registry_meta.rs / mod.rs),
//! `(workspace_id, event_id)` projection PK, label-driven gating, no
//! `current_recorded_by()` reads in the projector. Per-slice integrity is
//! verified via `blake3(slice_bytes) == slice_hash` in the slice projector;
//! the file's `bao_outboard` is retained for whole-file integrity checks at
//! save time (out of scope for this Wave 1 port — see plan.md).

pub mod codec;
pub mod projector;
pub mod queries;

// Re-export stable public API so callers import from `event_modules::file`.
pub use codec::{encode_file, parse_file, FileEvent, FILE_FIELDS, FILE_META};
pub use projector::project_pure;

use rusqlite::Connection;

/// `files` projection table.
///
/// Plan.md Stage 3.5 step 5C — drop the legacy `recorded_by` shadow
/// column. The PK is `(workspace_id, event_id)` (already migrated in
/// Stage 2); step 5C finishes the migration by removing the unused
/// shadow column and its index. Per-tenant queries against `files`
/// resolve the caller's workspace_id from `invites_accepted` and filter
/// on `WHERE workspace_id = ?1`.
pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    let needs_recreate = match pk_columns(conn, "files")? {
        Some(cols) => {
            cols != vec!["workspace_id".to_string(), "event_id".to_string()]
                || has_recorded_by(conn, "files")?
        }
        None => false,
    };
    if needs_recreate {
        conn.execute_batch("DROP TABLE IF EXISTS files")?;
    }
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS files (
            workspace_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            file_name TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            slice_count INTEGER NOT NULL,
            bao_outboard BLOB NOT NULL,
            content_hash BLOB NOT NULL,
            created_at_ms INTEGER NOT NULL,
            PRIMARY KEY (workspace_id, event_id)
        );
        CREATE INDEX IF NOT EXISTS idx_files_workspace_created
            ON files(workspace_id, created_at_ms DESC);
        ",
    )?;
    Ok(())
}

/// Returns true if the table has a legacy `recorded_by` column.
fn has_recorded_by(conn: &Connection, table: &str) -> rusqlite::Result<bool> {
    let pragma = format!("PRAGMA table_info({})", table);
    let mut stmt = conn.prepare(&pragma)?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == "recorded_by" {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Read the PRIMARY KEY column names for `table`, in PK ordinal order.
/// Returns `None` if the table does not exist.
fn pk_columns(conn: &Connection, table: &str) -> rusqlite::Result<Option<Vec<String>>> {
    let pragma = format!("PRAGMA table_info({})", table);
    let mut stmt = conn.prepare(&pragma)?;
    let mut rows = stmt.query([])?;
    let mut found_any = false;
    let mut pks: Vec<(i64, String)> = Vec::new();
    while let Some(row) = rows.next()? {
        found_any = true;
        let name: String = row.get(1)?;
        let pk: i64 = row.get(5)?;
        if pk > 0 {
            pks.push((pk, name));
        }
    }
    if !found_any {
        return Ok(None);
    }
    pks.sort_by_key(|p| p.0);
    Ok(Some(pks.into_iter().map(|p| p.1).collect()))
}
