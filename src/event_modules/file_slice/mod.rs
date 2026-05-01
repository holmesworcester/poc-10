//! `file_slice` event (type 46): one verified plaintext chunk of a larger
//! file. Many slices per `file` event; this is the bulk-IO event type that
//! dominates large-payload sync throughput.
//!
//! Wave 1 chain-friendly port. Per-slice integrity: the slice carries its
//! own `slice_hash = blake3(slice_bytes)`; the projector verifies the hash
//! match without needing any other event in context. The whole-file integrity
//! check (bao tree over `content_hash`) happens at file-save time using the
//! `file.bao_outboard` field — out of scope for this Wave 1 port.

pub mod codec;
pub mod projector;
pub mod stats;

pub use codec::{
    encode_file_slice, parse_file_slice, FileSliceEvent, FILE_SLICE_FIELDS, FILE_SLICE_META,
    MAX_SLICE_BYTES,
};
pub use projector::project_pure;
pub use stats::{file_slice_event_count, file_slice_event_counts_by_source};

use rusqlite::Connection;

/// `file_slices` projection table.
///
/// Plan.md Stage 3.5 step 5C — drop the legacy `recorded_by` shadow
/// column. Keyed by `(workspace_id, event_id)` (already migrated in
/// Stage 2) with a unique constraint on `(workspace_id, file_event_id,
/// slice_index)` to enforce one row per slot. Step 5C finishes the
/// migration by removing the unused shadow column.
pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    let needs_recreate = match pk_columns(conn, "file_slices")? {
        Some(cols) => {
            cols != vec!["workspace_id".to_string(), "event_id".to_string()]
                || has_recorded_by(conn, "file_slices")?
        }
        None => false,
    };
    if needs_recreate {
        conn.execute_batch("DROP TABLE IF EXISTS file_slices")?;
    }
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS file_slices (
            workspace_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            file_event_id TEXT NOT NULL,
            slice_index INTEGER NOT NULL,
            slice_hash BLOB NOT NULL,
            slice_bytes BLOB NOT NULL,
            created_at_ms INTEGER NOT NULL,
            PRIMARY KEY (workspace_id, event_id),
            UNIQUE (workspace_id, file_event_id, slice_index)
        );
        CREATE INDEX IF NOT EXISTS idx_file_slices_file
            ON file_slices(workspace_id, file_event_id, slice_index);
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
