use rusqlite::{Connection, OptionalExtension};
use std::time::{SystemTime, UNIX_EPOCH};

pub const CRED_SOURCE_UNKNOWN: &str = "unknown";
pub const CRED_SOURCE_RANDOM: &str = "random";
pub const CRED_SOURCE_BOOTSTRAP: &str = "bootstrap";
pub const CRED_SOURCE_PEER_SHARED: &str = "peershared";

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS local_transport_creds (
            peer_id TEXT PRIMARY KEY,
            cert_der BLOB NOT NULL,
            key_der BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            source TEXT NOT NULL DEFAULT 'unknown'
        );
        CREATE TABLE IF NOT EXISTS local_transport_targets (
            tenant_id TEXT PRIMARY KEY,
            transport_peer_id TEXT NOT NULL,
            source TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_local_transport_targets_transport_peer_id
            ON local_transport_targets(transport_peer_id);
        CREATE UNIQUE INDEX IF NOT EXISTS idx_local_transport_targets_peershared_owner
            ON local_transport_targets(transport_peer_id)
            WHERE source = 'peershared';
        ",
    )?;
    // Schema epoch is fixed for this POC, but allow additive column convergence so
    // existing DBs in this epoch continue to open.
    let has_source = {
        let mut stmt = conn.prepare("PRAGMA table_info(local_transport_creds)")?;
        let mut rows = stmt.query([])?;
        let mut found = false;
        while let Some(row) = rows.next()? {
            let name: String = row.get(1)?;
            if name == "source" {
                found = true;
                break;
            }
        }
        found
    };
    if !has_source {
        conn.execute(
            "ALTER TABLE local_transport_creds ADD COLUMN source TEXT NOT NULL DEFAULT 'unknown'",
            [],
        )?;
    }
    let target_table_sql: Option<String> = conn
        .query_row(
            "SELECT sql
             FROM sqlite_master
             WHERE type = 'table'
               AND name = 'local_transport_targets'
             LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()?;
    if target_table_sql
        .as_deref()
        .map(|sql| sql.contains("transport_peer_id TEXT NOT NULL UNIQUE"))
        .unwrap_or(false)
    {
        conn.execute_batch(
            "
            ALTER TABLE local_transport_targets RENAME TO local_transport_targets_old;
            CREATE TABLE local_transport_targets (
                tenant_id TEXT PRIMARY KEY,
                transport_peer_id TEXT NOT NULL,
                source TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            INSERT OR REPLACE INTO local_transport_targets (tenant_id, transport_peer_id, source, created_at)
            SELECT tenant_id, transport_peer_id, source, created_at
            FROM local_transport_targets_old
            ORDER BY CASE source
                         WHEN 'peershared' THEN 0
                         WHEN 'bootstrap' THEN 1
                         ELSE 2
                     END,
                     created_at ASC,
                     tenant_id ASC;
            DROP TABLE local_transport_targets_old;
            CREATE INDEX IF NOT EXISTS idx_local_transport_targets_transport_peer_id
                ON local_transport_targets(transport_peer_id);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_local_transport_targets_peershared_owner
                ON local_transport_targets(transport_peer_id)
                WHERE source = 'peershared';
            ",
        )?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalTransportTarget {
    pub tenant_id: String,
    pub transport_peer_id: String,
    pub source: String,
}

/// Record the tenant's current local transport target.
///
/// This is replay-derived local routing state owned by the projection
/// pipeline (`write_exec.rs`). The adapter materializes cert/key bytes,
/// and the pipeline records which transport fingerprint is active for
/// each tenant. This table is the sole authority for tenant discovery.
pub fn set_local_transport_target(
    conn: &Connection,
    tenant_id: &str,
    transport_peer_id: &str,
    source: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let conflicting_owner: Option<(String, String)> = conn
        .query_row(
            "SELECT tenant_id, source
             FROM local_transport_targets
             WHERE transport_peer_id = ?1
               AND tenant_id != ?2
             ORDER BY CASE source
                          WHEN 'peershared' THEN 0
                          WHEN 'bootstrap' THEN 1
                          ELSE 2
                      END,
                      created_at ASC,
                      tenant_id ASC
             LIMIT 1",
            rusqlite::params![transport_peer_id, tenant_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((existing_tenant_id, existing_source)) = conflicting_owner {
        if source == CRED_SOURCE_PEER_SHARED || existing_source == CRED_SOURCE_PEER_SHARED {
            return Err(format!(
                "failed to set local transport target tenant={} transport_peer_id={} source={}: already owned by tenant={} source={}",
                tenant_id, transport_peer_id, source, existing_tenant_id, existing_source
            )
            .into());
        }
    }

    if let Err(err) = conn.execute(
        "INSERT INTO local_transport_targets (tenant_id, transport_peer_id, source, created_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(tenant_id) DO UPDATE SET
             transport_peer_id = excluded.transport_peer_id,
             source = excluded.source,
             created_at = excluded.created_at
         WHERE excluded.source = 'peershared'
            OR local_transport_targets.source != 'peershared'",
        rusqlite::params![tenant_id, transport_peer_id, source, now],
    ) {
        let existing: Option<(String, String)> = conn
            .query_row(
                "SELECT tenant_id, source
                 FROM local_transport_targets
                 WHERE transport_peer_id = ?1
                 LIMIT 1",
                rusqlite::params![transport_peer_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        if let Some((existing_tenant_id, existing_source)) = existing {
            return Err(format!(
                "failed to set local transport target tenant={} transport_peer_id={} source={}: already owned by tenant={} source={}: {}",
                tenant_id,
                transport_peer_id,
                source,
                existing_tenant_id,
                existing_source,
                err
            )
            .into());
        }
        return Err(format!(
            "failed to set local transport target tenant={} transport_peer_id={} source={}: {}",
            tenant_id, transport_peer_id, source, err
        )
        .into());
    }
    Ok(())
}

pub fn resolve_local_transport_target(
    conn: &Connection,
    transport_peer_id: &str,
) -> Result<Option<LocalTransportTarget>, Box<dyn std::error::Error + Send + Sync>> {
    Ok(resolve_local_transport_targets(conn, transport_peer_id)?
        .into_iter()
        .next())
}

pub fn resolve_local_transport_targets(
    conn: &Connection,
    transport_peer_id: &str,
) -> Result<Vec<LocalTransportTarget>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stmt = conn.prepare(
        "SELECT tenant_id, transport_peer_id, source
         FROM local_transport_targets
         WHERE transport_peer_id = ?1
         ORDER BY CASE source
                      WHEN 'peershared' THEN 0
                      WHEN 'bootstrap' THEN 1
                      ELSE 2
                  END,
                  created_at ASC,
                  tenant_id ASC",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![transport_peer_id], |row| {
            Ok(LocalTransportTarget {
                tenant_id: row.get(0)?,
                transport_peer_id: row.get(1)?,
                source: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

pub fn resolve_tenant_transport_target(
    conn: &Connection,
    tenant_id: &str,
) -> Result<Option<LocalTransportTarget>, Box<dyn std::error::Error + Send + Sync>> {
    let target = conn
        .query_row(
            "SELECT tenant_id, transport_peer_id, source
             FROM local_transport_targets
             WHERE tenant_id = ?1
             LIMIT 1",
            rusqlite::params![tenant_id],
            |row| {
                Ok(LocalTransportTarget {
                    tenant_id: row.get(0)?,
                    transport_peer_id: row.get(1)?,
                    source: row.get(2)?,
                })
            },
        )
        .optional()?;
    Ok(target)
}

/// Store TLS cert/key DER blobs for a local peer identity.
pub fn store_local_creds(
    conn: &Connection,
    peer_id: &str,
    cert_der: &[u8],
    key_der: &[u8],
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    store_local_creds_with_source(conn, peer_id, cert_der, key_der, CRED_SOURCE_UNKNOWN)
}

/// Store TLS cert/key DER blobs for a local peer identity with explicit source.
pub fn store_local_creds_with_source(
    conn: &Connection,
    peer_id: &str,
    cert_der: &[u8],
    key_der: &[u8],
    source: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    conn.execute(
        "INSERT OR REPLACE INTO local_transport_creds (peer_id, cert_der, key_der, created_at, source) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![peer_id, cert_der, key_der, now, source],
    )?;
    Ok(())
}

/// Return true if any local credential row has the given source marker.
pub fn has_creds_with_source(
    conn: &Connection,
    source: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let exists: i64 = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM local_transport_creds WHERE source = ?1 LIMIT 1)",
        rusqlite::params![source],
        |row| row.get(0),
    )?;
    Ok(exists != 0)
}

/// Return true if a specific peer_id has a local credential row with `source`.
pub fn peer_has_creds_with_source(
    conn: &Connection,
    peer_id: &str,
    source: &str,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let exists: i64 = conn.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM local_transport_creds
             WHERE peer_id = ?1
               AND source = ?2
             LIMIT 1
         )",
        rusqlite::params![peer_id, source],
        |row| row.get(0),
    )?;
    Ok(exists != 0)
}

/// Load cert/key DER blobs for a specific peer identity.
pub fn load_local_creds(
    conn: &Connection,
    peer_id: &str,
) -> Result<Option<(Vec<u8>, Vec<u8>)>, Box<dyn std::error::Error + Send + Sync>> {
    match conn.query_row(
        "SELECT cert_der, key_der FROM local_transport_creds WHERE peer_id = ?1",
        rusqlite::params![peer_id],
        |row| Ok((row.get::<_, Vec<u8>>(0)?, row.get::<_, Vec<u8>>(1)?)),
    ) {
        Ok(pair) => Ok(Some(pair)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Load the sole local transport credentials.
/// Returns (peer_id, cert_der, key_der) if exactly one exists.
/// Returns None if no credentials exist.
/// Errors if multiple credentials exist (ambiguous — multi-tenant is handled automatically by run_node).
pub fn load_sole_local_creds(
    conn: &Connection,
) -> Result<Option<(String, Vec<u8>, Vec<u8>)>, Box<dyn std::error::Error + Send + Sync>> {
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM local_transport_creds", [], |row| {
        row.get(0)
    })?;
    if count == 0 {
        return Ok(None);
    }
    if count > 1 {
        return Err(format!(
            "Multiple local identities found ({}). Multi-tenant is handled automatically.",
            count
        )
        .into());
    }
    match conn.query_row(
        "SELECT peer_id, cert_der, key_der FROM local_transport_creds LIMIT 1",
        [],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, Vec<u8>>(1)?,
                row.get::<_, Vec<u8>>(2)?,
            ))
        },
    ) {
        Ok(triple) => Ok(Some(triple)),
        Err(e) => Err(e.into()),
    }
}

/// List all peer_ids that have stored transport credentials.
pub fn list_local_peers(
    conn: &Connection,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stmt = conn.prepare("SELECT peer_id FROM local_transport_creds ORDER BY created_at")?;
    let peers = stmt
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(peers)
}

/// List all local transport keys with their source (e.g. "random", "peershared", "bootstrap").
pub fn list_local_peers_with_source(
    conn: &Connection,
) -> Result<Vec<serde_json::Value>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stmt =
        conn.prepare("SELECT peer_id, source FROM local_transport_creds ORDER BY created_at")?;
    let keys = stmt
        .query_map([], |row| {
            Ok(serde_json::json!({
                "peer_id": row.get::<_, String>(0)?,
                "source": row.get::<_, String>(1)?,
            }))
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(keys)
}

/// Tenant discovery: resolve local tenants purely from replay-derived
/// `local_transport_targets` joined with `local_transport_creds` and
/// `invites_accepted`. No heuristic inference — if the projection
/// pipeline hasn't recorded a target mapping, the tenant won't appear.
pub struct TenantInfo {
    pub peer_id: String,
    pub workspace_id: String,
    pub transport_peer_id: String,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Stage 3.5 endpoint/workspace APIs (recorded_by removal — codex plan).
//
// New world: events are routed by `workspace_id`; the daemon has a single
// `EndpointIdentity` (the `daemon_transport_identity` singleton) and hosts
// zero or more `WorkspaceBinding`s, one per accepted invite.
// ---------------------------------------------------------------------------

/// The singleton local endpoint identity (one per daemon).
#[derive(Debug, Clone)]
pub struct EndpointIdentity {
    /// 32-byte SPKI fingerprint encoded as hex.
    pub endpoint_id: String,
    pub cert_der: Vec<u8>,
    pub key_der: Vec<u8>,
}

/// A workspace this daemon hosts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceBinding {
    /// Base64-encoded `workspace_id`.
    pub workspace_id: String,
}

/// Load the singleton local endpoint identity used by the daemon's
/// transport substrate.
///
/// Returns `Ok(None)` when no daemon identity has been provisioned yet.
pub fn load_local_endpoint(
    conn: &Connection,
) -> Result<Option<EndpointIdentity>, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(row) = crate::db::daemon_identity::load(conn)? {
        return Ok(Some(EndpointIdentity {
            endpoint_id: row.peer_id,
            cert_der: row.cert_der,
            key_der: row.key_der,
        }));
    }
    // Pre-substrate fall-back: the legacy `local_transport_creds` table holds
    // a singleton row in the new daemon path.
    if let Some((peer_id, cert_der, key_der)) = load_sole_local_creds(conn)? {
        return Ok(Some(EndpointIdentity {
            endpoint_id: peer_id,
            cert_der,
            key_der,
        }));
    }
    Ok(None)
}

/// Enumerate workspaces this daemon hosts (one per `invites_accepted.workspace_id`
/// distinct row).
pub fn list_hosted_workspaces(
    conn: &Connection,
) -> Result<Vec<WorkspaceBinding>, Box<dyn std::error::Error + Send + Sync>> {
    let mut stmt = conn.prepare(
        "SELECT DISTINCT workspace_id
         FROM invites_accepted
         ORDER BY workspace_id ASC",
    )?;
    let rows = stmt
        .query_map([], |row| {
            Ok(WorkspaceBinding {
                workspace_id: row.get(0)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

// `discover_local_tenants` was retired in the recorded_by sweep — it joined
// `invites_accepted` on the legacy `recorded_by` shadow column. The
// substrate's tenant-discovery surface is `list_hosted_workspaces` plus
// `list_local_peers`/`load_local_endpoint`.
//
// This stub is retained so legacy `#[ignore]`'d tests in `tests/rpc_test.rs`
// and `tests/cli_harness/mod.rs` continue to compile; it always returns an
// empty list.
pub fn discover_local_tenants(
    _conn: &Connection,
) -> Result<Vec<TenantInfo>, Box<dyn std::error::Error + Send + Sync>> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;

    // ---------------------------------------------------------------------
    // Stage 3.5: tests for the new endpoint/workspace APIs.
    // ---------------------------------------------------------------------

    #[test]
    fn test_load_local_endpoint_prefers_daemon_identity() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        // Empty DB returns None.
        assert!(load_local_endpoint(&conn).unwrap().is_none());

        // With only legacy `local_transport_creds`, the fall-back path
        // returns a singleton.
        store_local_creds(&conn, "legacy-peer", b"cert-l", b"key-l").unwrap();
        let id = load_local_endpoint(&conn).unwrap().expect("legacy fallback");
        assert_eq!(id.endpoint_id, "legacy-peer");
        assert_eq!(id.cert_der, b"cert-l");

        // When the daemon_transport_identity row exists, that wins.
        crate::db::daemon_identity::store(&conn, "daemon-peer", b"cert-d", b"key-d").unwrap();
        let id = load_local_endpoint(&conn).unwrap().expect("daemon identity");
        assert_eq!(id.endpoint_id, "daemon-peer");
        assert_eq!(id.cert_der, b"cert-d");
    }

    #[test]
    fn test_list_hosted_workspaces_distinct_per_workspace() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        assert!(list_hosted_workspaces(&conn).unwrap().is_empty());

        // One accepted invite per workspace.
        conn.execute(
            "INSERT INTO invites_accepted (workspace_id, event_id, tenant_event_id, invite_event_id, created_at)
             VALUES ('ws-1', 'ia-a1', 't-a1', 'inv-a1', 1)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO invites_accepted (workspace_id, event_id, tenant_event_id, invite_event_id, created_at)
             VALUES ('ws-1', 'ia-b1', 't-b1', 'inv-b1', 2)",
            [],
        ).unwrap();
        conn.execute(
            "INSERT INTO invites_accepted (workspace_id, event_id, tenant_event_id, invite_event_id, created_at)
             VALUES ('ws-2', 'ia-a2', 't-a2', 'inv-a2', 3)",
            [],
        ).unwrap();

        let bindings = list_hosted_workspaces(&conn).unwrap();
        assert_eq!(bindings.len(), 2, "one binding per workspace_id");
        let ids: Vec<&str> = bindings.iter().map(|b| b.workspace_id.as_str()).collect();
        assert!(ids.contains(&"ws-1"));
        assert!(ids.contains(&"ws-2"));
    }

    #[test]
    fn test_store_and_load_creds() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        let peer_id = "abc123";
        let cert = b"cert_data";
        let key = b"key_data";
        store_local_creds(&conn, peer_id, cert, key).unwrap();

        let loaded = load_local_creds(&conn, peer_id).unwrap();
        assert!(loaded.is_some());
        let (c, k) = loaded.unwrap();
        assert_eq!(c, cert);
        assert_eq!(k, key);
    }

    #[test]
    fn test_load_missing_returns_none() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        assert!(load_local_creds(&conn, "nonexistent").unwrap().is_none());
    }

    #[test]
    fn test_load_sole_local_creds() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        assert!(load_sole_local_creds(&conn).unwrap().is_none());

        store_local_creds(&conn, "peer1", b"c1", b"k1").unwrap();
        let result = load_sole_local_creds(&conn).unwrap().unwrap();
        assert_eq!(result.0, "peer1");
    }

    #[test]
    fn test_load_sole_local_creds_rejects_multiple() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        store_local_creds(&conn, "peer1", b"c1", b"k1").unwrap();
        store_local_creds(&conn, "peer2", b"c2", b"k2").unwrap();

        let err = load_sole_local_creds(&conn).unwrap_err();
        assert!(
            err.to_string().contains("Multiple local identities"),
            "should reject ambiguous multi-tenant DB, got: {}",
            err
        );
    }

    #[test]
    fn test_list_local_peers() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        store_local_creds(&conn, "peer_a", b"c1", b"k1").unwrap();
        store_local_creds(&conn, "peer_b", b"c2", b"k2").unwrap();

        let peers = list_local_peers(&conn).unwrap();
        assert_eq!(peers.len(), 2);
        assert!(peers.contains(&"peer_a".to_string()));
        assert!(peers.contains(&"peer_b".to_string()));
    }

    #[test]
    fn test_store_replaces_existing() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        store_local_creds(&conn, "peer1", b"old_cert", b"old_key").unwrap();
        store_local_creds(&conn, "peer1", b"new_cert", b"new_key").unwrap();

        let (c, k) = load_local_creds(&conn, "peer1").unwrap().unwrap();
        assert_eq!(c, b"new_cert");
        assert_eq!(k, b"new_key");

        assert_eq!(list_local_peers(&conn).unwrap().len(), 1);
    }

    #[test]
    fn test_resolve_local_transport_target() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        assert!(resolve_local_transport_target(&conn, "peer1")
            .unwrap()
            .is_none());

        set_local_transport_target(&conn, "tenant_a", "peer1", CRED_SOURCE_BOOTSTRAP).unwrap();

        assert_eq!(
            resolve_local_transport_target(&conn, "peer1").unwrap(),
            Some(LocalTransportTarget {
                tenant_id: "tenant_a".to_string(),
                transport_peer_id: "peer1".to_string(),
                source: CRED_SOURCE_BOOTSTRAP.to_string(),
            })
        );
    }

    #[test]
    fn test_resolve_tenant_transport_target() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        assert!(resolve_tenant_transport_target(&conn, "tenant_a")
            .unwrap()
            .is_none());

        set_local_transport_target(&conn, "tenant_a", "peer1", CRED_SOURCE_BOOTSTRAP).unwrap();

        assert_eq!(
            resolve_tenant_transport_target(&conn, "tenant_a").unwrap(),
            Some(LocalTransportTarget {
                tenant_id: "tenant_a".to_string(),
                transport_peer_id: "peer1".to_string(),
                source: CRED_SOURCE_BOOTSTRAP.to_string(),
            })
        );
    }

    #[test]
    fn test_bootstrap_transport_target_can_be_shared_across_tenants() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        set_local_transport_target(&conn, "tenant_a", "bootstrap_peer", CRED_SOURCE_BOOTSTRAP)
            .unwrap();
        set_local_transport_target(&conn, "tenant_b", "bootstrap_peer", CRED_SOURCE_BOOTSTRAP)
            .unwrap();

        let targets = resolve_local_transport_targets(&conn, "bootstrap_peer").unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].tenant_id, "tenant_a");
        assert_eq!(targets[1].tenant_id, "tenant_b");
    }

    #[test]
    fn test_peershared_transport_target_stays_unique_across_tenants() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        set_local_transport_target(&conn, "tenant_a", "shared_peer", CRED_SOURCE_PEER_SHARED)
            .unwrap();
        let err =
            set_local_transport_target(&conn, "tenant_b", "shared_peer", CRED_SOURCE_BOOTSTRAP)
                .unwrap_err();
        assert!(
            err.to_string().contains("already owned"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn test_bootstrap_cannot_overwrite_peershared_target() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        // peershared is set first
        set_local_transport_target(
            &conn,
            "tenant_a",
            "peershared_peer",
            CRED_SOURCE_PEER_SHARED,
        )
        .unwrap();

        // bootstrap for the same tenant must not overwrite peershared
        set_local_transport_target(&conn, "tenant_a", "bootstrap_peer", CRED_SOURCE_BOOTSTRAP)
            .unwrap();

        let target = resolve_tenant_transport_target(&conn, "tenant_a")
            .unwrap()
            .expect("target should exist");
        assert_eq!(target.transport_peer_id, "peershared_peer");
        assert_eq!(target.source, CRED_SOURCE_PEER_SHARED);
    }

    #[test]
    fn test_peershared_overwrites_bootstrap_target() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        // bootstrap is set first
        set_local_transport_target(&conn, "tenant_a", "bootstrap_peer", CRED_SOURCE_BOOTSTRAP)
            .unwrap();

        // peershared for the same tenant must overwrite bootstrap
        set_local_transport_target(
            &conn,
            "tenant_a",
            "peershared_peer",
            CRED_SOURCE_PEER_SHARED,
        )
        .unwrap();

        let target = resolve_tenant_transport_target(&conn, "tenant_a")
            .unwrap()
            .expect("target should exist");
        assert_eq!(target.transport_peer_id, "peershared_peer");
        assert_eq!(target.source, CRED_SOURCE_PEER_SHARED);
    }

    #[test]
    fn test_has_creds_with_source() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        store_local_creds_with_source(&conn, "peer1", b"cert1", b"key1", CRED_SOURCE_BOOTSTRAP)
            .unwrap();

        assert!(has_creds_with_source(&conn, CRED_SOURCE_BOOTSTRAP).unwrap());
        assert!(!has_creds_with_source(&conn, CRED_SOURCE_PEER_SHARED).unwrap());
    }

    #[test]
    fn test_peer_has_creds_with_source() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();
        store_local_creds_with_source(&conn, "peer1", b"cert1", b"key1", CRED_SOURCE_BOOTSTRAP)
            .unwrap();
        store_local_creds_with_source(&conn, "peer2", b"cert2", b"key2", CRED_SOURCE_PEER_SHARED)
            .unwrap();

        assert!(peer_has_creds_with_source(&conn, "peer1", CRED_SOURCE_BOOTSTRAP).unwrap());
        assert!(!peer_has_creds_with_source(&conn, "peer1", CRED_SOURCE_PEER_SHARED).unwrap());
        assert!(peer_has_creds_with_source(&conn, "peer2", CRED_SOURCE_PEER_SHARED).unwrap());
    }

}
