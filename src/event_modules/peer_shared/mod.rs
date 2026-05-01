pub mod projector;
pub mod queries;
pub mod codec;

pub use projector::project_pure;
pub use queries::{
    count, first_event_id, identity, list_event_ids, list_peers, list_tenant_items, list_tenants,
    load_local_peer_signer, load_local_peer_signer_required,
    resolve_event_id_by_transport_fingerprint, resolve_user_event_id, IdentityResponse, PeerItem,
    TenantItem, TenantRow,
};
pub use codec::{
    encode_peer_shared, parse_peer_shared, PeerSharedEvent, PEER_SHARED_META, PEER_SHARED_WIRE_SIZE,
};

use rusqlite::Connection;

fn column_exists(conn: &Connection, table: &str, column: &str) -> rusqlite::Result<bool> {
    let pragma = format!("PRAGMA table_info({table})");
    let mut stmt = conn.prepare(&pragma)?;
    let mut rows = stmt.query([])?;
    while let Some(row) = rows.next()? {
        let name: String = row.get(1)?;
        if name == column {
            return Ok(true);
        }
    }
    Ok(false)
}

/// `peers_shared` projection table.
///
/// Plan.md round-9 step 5A — drop the legacy `recorded_by` shadow column.
/// The PK is `(workspace_id, event_id)` (already migrated in Stage 2);
/// step 5A finishes the migration by removing the unused shadow column
/// and its associated indexes. Per-tenant queries against `peers_shared`
/// resolve the caller's workspace_id from `invites_accepted` and filter
/// on `WHERE workspace_id = ?1`.
///
/// For poc-8/9 dev we DROP+CREATE on schema-init when the existing PK shape
/// doesn't match or the table still carries the legacy `recorded_by` column.
pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    let needs_recreate = match table_state(conn, "peers_shared")? {
        Some(state) => {
            state.pk != vec!["workspace_id".to_string(), "event_id".to_string()]
                || state.has_recorded_by
        }
        None => false,
    };
    if needs_recreate {
        conn.execute_batch("DROP TABLE IF EXISTS peers_shared")?;
    }
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS peers_shared (
            workspace_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            public_key BLOB NOT NULL,
            transport_fingerprint BLOB,
            user_event_id TEXT,
            device_name TEXT,
            PRIMARY KEY (workspace_id, event_id)
        );
        ",
    )?;
    if !column_exists(conn, "peers_shared", "transport_fingerprint")? {
        conn.execute(
            "ALTER TABLE peers_shared ADD COLUMN transport_fingerprint BLOB",
            [],
        )?;
    }
    conn.execute_batch(
        "
        CREATE INDEX IF NOT EXISTS idx_peers_shared_event_id
            ON peers_shared(event_id);
        CREATE INDEX IF NOT EXISTS idx_peers_shared_transport_fingerprint
            ON peers_shared(workspace_id, transport_fingerprint);
        ",
    )?;
    Ok(())
}

struct TableState {
    pk: Vec<String>,
    has_recorded_by: bool,
}

fn table_state(conn: &Connection, table: &str) -> rusqlite::Result<Option<TableState>> {
    let pragma = format!("PRAGMA table_info({})", table);
    let mut stmt = conn.prepare(&pragma)?;
    let mut rows = stmt.query([])?;
    let mut found_any = false;
    let mut pks: Vec<(i64, String)> = Vec::new();
    let mut has_recorded_by = false;
    while let Some(row) = rows.next()? {
        found_any = true;
        let name: String = row.get(1)?;
        let pk: i64 = row.get(5)?;
        if pk > 0 {
            pks.push((pk, name.clone()));
        }
        if name == "recorded_by" {
            has_recorded_by = true;
        }
    }
    if !found_any {
        return Ok(None);
    }
    pks.sort_by_key(|p| p.0);
    Ok(Some(TableState {
        pk: pks.into_iter().map(|p| p.1).collect(),
        has_recorded_by,
    }))
}
