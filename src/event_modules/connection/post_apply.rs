//! Post-apply maintenance for `Connection` events.
//!
//! When a `Connection` event reaches `Applied` (either authored locally
//! and projected by the dispatcher, or received via the bootstrap-wrap
//! path on the responder side), the side that observes the apply runs
//! [`apply_connection_post`] to:
//!
//! - derive a deterministic `connection_secret_id` and AEAD key from
//!   the sorted endpoint pair + the canonical `connection_id` and write
//!   inbound + outbound rows into `connection_secrets`,
//! - record `connection_endpoints(connection_id -> remote_endpoint_id)`
//!   so the per-connection sender actor (started by the dispatcher's
//!   outbox step on the next outbox row) can dial the right peer,
//! - emit one root-node `CompareEvent` so the receiving side starts the
//!   negentropy fold against this side's local sync tree.
//!
//! The function is invoked from `runtime/control_loop/inbound_step/
//! dispatch.rs::project_and_apply` after a Connection event applies. It
//! is intentionally event-module code (not substrate) so it stays
//! reachable for both the inbound chain and the local-authoring path.

use rusqlite::{params, Connection as SqlConnection};

use super::event::Connection;
use super::local_signing_key;
use super::secrets::{upsert as upsert_secret, SecretDirection, SecretRow};
use super::wrap::{connection_secret_id, connection_secret_key, ecdh_shared_secret};
use crate::event_modules::sync::compare::{codec as compare_codec, event::CompareEvent};
use crate::projection::contract::{SqlVal, WriteOp};
use crate::runtime::control_loop::work_item::{BlakeId, EndpointId, WorkspaceId};
use crate::state::events_canonical::{EventScope, EventStatus};

/// Connection-secret TTL. POC value — large enough to outlive the test
/// run; production rotation lives in a different code path.
const SECRET_TTL_MS: i64 = 24 * 60 * 60 * 1000; // 24h

/// Run all post-apply effects synchronously inside the caller's
/// transaction. Returns Ok even if the connection was authored against
/// an unknown local endpoint — secrets are derived purely from the
/// canonical event so the symmetric apply on the other side will
/// produce matching rows.
pub fn apply_connection_post(
    db: &SqlConnection,
    ev: &Connection,
    local_endpoint_id: &EndpointId,
    now_ms: i64,
) -> rusqlite::Result<()> {
    // Identify remote endpoint. If neither endpoint matches the local
    // identity, treat the event as informational — the other side will
    // do the work.
    let remote_endpoint_id = if &ev.endpoint_a == local_endpoint_id {
        ev.endpoint_b
    } else if &ev.endpoint_b == local_endpoint_id {
        ev.endpoint_a
    } else {
        return Ok(());
    };

    let connection_id = ev.canonical_event_id();

    // Real X25519 ECDH between THIS daemon's static signing key and the
    // canonical-event endpoints. Both sides observe the same applied
    // Connection event, do the same ECDH against their own private key
    // and the other endpoint's pubkey, and end up with bit-identical
    // shared secrets. We then split the shared secret into separate
    // outbound / inbound keys + secret-ids using `connection_secret_key`
    // / `connection_secret_id` (blake3 keyed by the shared secret with
    // domain-separated info strings).
    let local_signing = local_signing_key::for_db(db);
    let shared = match ecdh_shared_secret(&local_signing, &remote_endpoint_id) {
        Ok(s) => s,
        Err(_) => {
            // Remote endpoint id failed to parse as ed25519. Production
            // never produces these — log + skip.
            tracing::warn!(
                target: "event_modules::connection::post_apply",
                remote_endpoint = ?remote_endpoint_id,
                "remote endpoint id is not a valid ed25519 pubkey; skipping secret derivation"
            );
            return Ok(());
        }
    };

    let (low, high) = if ev.endpoint_a <= ev.endpoint_b {
        (ev.endpoint_a, ev.endpoint_b)
    } else {
        (ev.endpoint_b, ev.endpoint_a)
    };

    // Single key + single id per connection — the bidirectional channel
    // shares one AEAD key, but the table keeps separate inbound /
    // outbound rows so wrap/unwrap can scope by direction (and a future
    // rotation step can mint distinct keys per direction without
    // touching the lookup paths).
    let secret_id = connection_secret_id(&shared, &low, &high, &connection_id);
    let key = connection_secret_key(&shared, &low, &high, &connection_id);

    upsert_secret(
        db,
        &SecretRow {
            connection_secret_id: secret_id,
            key,
            direction: SecretDirection::Outbound,
            connection_id,
            ttl_ms: SECRET_TTL_MS,
            created_at_ms: now_ms,
        },
    )?;
    upsert_secret(
        db,
        &SecretRow {
            connection_secret_id: secret_id,
            key,
            direction: SecretDirection::Inbound,
            connection_id,
            ttl_ms: SECRET_TTL_MS,
            created_at_ms: now_ms,
        },
    )?;

    // Record the (connection_id -> remote_endpoint_id) mapping the
    // sender actor reads.
    crate::runtime::jobs::sender::ensure_connection_endpoints_schema(db)?;
    crate::runtime::jobs::sender::upsert_connection_endpoint(db, connection_id, remote_endpoint_id)?;

    // Best-effort: if we have an unattributed inbound observation
    // (remote_endpoint_id NULL but ip/port populated by the accept
    // loop), promote it to this remote endpoint's
    // `endpoint_addresses` row so our outbound sender can dial back.
    // The responder (the side that received the bootstrap frame)
    // typically lacks the initiator's address in any other channel.
    if let Some((ip, port)) = recent_inbound_addr(db)? {
        let addr_str = format!("{}:{}", ip, port);
        if let Ok(addr) = addr_str.parse::<std::net::SocketAddr>() {
            let _ = crate::runtime::transport_v2::upsert_endpoint_address(
                db,
                &remote_endpoint_id,
                &addr,
            );
        }
    }

    // Record this connection's round-driver state. Both sides observe
    // the same canonical Connection event and write a row keyed by
    // connection_id; the row's `local_endpoint_id < remote_endpoint_id`
    // test deterministically picks ONE side as the round driver, so
    // both sides don't simultaneously kick off fresh negentropy rounds.
    crate::event_modules::sync::round_state::ensure_schema(db)?;
    crate::event_modules::sync::round_state::upsert(
        db,
        &connection_id,
        local_endpoint_id,
        &remote_endpoint_id,
        now_ms,
    )?;

    // Kick off sync from the driver side only. Both sides have the
    // shared workspaces enumerated on the canonical event, but only
    // the lex-smaller endpoint emits the on-connect root Compare —
    // the responder's reply is what brings the bidirectional
    // compare/have/need flow up.
    if crate::event_modules::sync::round_state::is_driver(local_endpoint_id, &remote_endpoint_id) {
        for workspace_id in &ev.shared_workspaces {
            emit_root_compare(db, &connection_id, workspace_id, now_ms)?;
        }
        crate::event_modules::sync::round_state::mark_root_compare_emitted(
            db,
            &connection_id,
            now_ms,
        )?;
    }

    Ok(())
}

/// Emit an endpoint-local root `CompareEvent` for `(connection_id,
/// workspace_id)`. The fingerprint is read from the local
/// `negentropy_tree` (zero on the first emit, before any durable apply).
pub fn emit_root_compare(
    db: &SqlConnection,
    connection_id: &BlakeId,
    workspace_id: &WorkspaceId,
    now_ms: i64,
) -> rusqlite::Result<()> {
    let fp =
        crate::event_modules::sync::negentropy_tree::query::node_fingerprint(db, workspace_id, &[])
            .unwrap_or([0u8; 32]);
    let ev = CompareEvent {
        connection_id: *connection_id,
        workspace_id: *workspace_id,
        node_id: Vec::new(),
        fingerprint: fp,
        created_at_ms: now_ms as u64,
    };
    let bytes = compare_codec::encode(&ev);
    let event_id = blake3_id(&bytes);
    // Insert events_canonical row (endpoint-local, applied).
    let ec = WriteOp::InsertOrIgnore {
        table: "events_canonical",
        columns: vec![
            "event_id",
            "canonical_event_bytes",
            "workspace_id",
            "scope",
            "status",
            "created_at_ms",
        ],
        values: vec![
            SqlVal::Blob(event_id.to_vec()),
            SqlVal::Blob(bytes),
            SqlVal::Blob(workspace_id.to_vec()),
            SqlVal::Text(EventScope::EndpointLocal.as_str().to_string()),
            SqlVal::Text(EventStatus::Applied.as_str().to_string()),
            SqlVal::Int(now_ms),
        ],
    };
    let ob = WriteOp::InsertOrIgnore {
        table: "outbox",
        columns: vec!["connection_id", "event_id", "queued_at_ms"],
        values: vec![
            SqlVal::Blob(connection_id.to_vec()),
            SqlVal::Blob(event_id.to_vec()),
            SqlVal::Int(now_ms),
        ],
    };
    apply_ops(db, &[ec, ob])
}

/// Find every connection sharing `workspace_id` and emit a root-node
/// CompareEvent into its outbox. Called from
/// `event_modules/sync/maintenance.rs::after_durable_apply` after a
/// durable event lands so peers learn the new fingerprint without
/// waiting on a periodic tick.
///
/// If `connection_shared_workspaces` does not yet exist (some legacy
/// in-memory test setups skip the connection schema bootstrap), this
/// is a no-op.
pub fn emit_root_compares_for_workspace(
    db: &SqlConnection,
    workspace_id: &WorkspaceId,
    now_ms: i64,
) -> rusqlite::Result<()> {
    if !table_exists(db, "connection_shared_workspaces")? {
        return Ok(());
    }
    let conn_ids = list_connections_for_workspace(db, workspace_id)?;
    for cid in conn_ids {
        emit_root_compare(db, &cid, workspace_id, now_ms)?;
    }
    Ok(())
}

fn table_exists(db: &SqlConnection, name: &str) -> rusqlite::Result<bool> {
    use rusqlite::OptionalExtension;
    let res: Option<String> = db
        .query_row(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?1",
            params![name],
            |r| r.get(0),
        )
        .optional()?;
    Ok(res.is_some())
}

fn list_connections_for_workspace(
    db: &SqlConnection,
    workspace_id: &WorkspaceId,
) -> rusqlite::Result<Vec<BlakeId>> {
    let mut stmt = db.prepare(
        "SELECT connection_id FROM connection_shared_workspaces WHERE workspace_id = ?1",
    )?;
    let mut rows = stmt.query(params![workspace_id.to_vec()])?;
    let mut conn_ids: Vec<BlakeId> = Vec::new();
    while let Some(r) = rows.next()? {
        let blob: Vec<u8> = r.get(0)?;
        if blob.len() == 32 {
            let mut id = [0u8; 32];
            id.copy_from_slice(&blob);
            conn_ids.push(id);
        }
    }
    Ok(conn_ids)
}

/// Most recent inbound observation that has IP/port populated but no
/// remote_endpoint_id resolution — that's the bootstrap-mode frame
/// the responder just received but hasn't attributed to an endpoint.
fn recent_inbound_addr(db: &SqlConnection) -> rusqlite::Result<Option<(String, u16)>> {
    use rusqlite::OptionalExtension;
    let row: Option<(String, i64)> = db
        .query_row(
            "SELECT ip, port FROM inbound_observations
             WHERE remote_endpoint_id IS NULL
               AND ip IS NOT NULL
               AND port IS NOT NULL
             ORDER BY first_seen_at_ms DESC
             LIMIT 1",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    match row {
        Some((ip, port)) if port >= 0 && port <= u16::MAX as i64 => Ok(Some((ip, port as u16))),
        _ => Ok(None),
    }
}

fn blake3_id(bytes: &[u8]) -> BlakeId {
    let mut id = [0u8; 32];
    id.copy_from_slice(blake3::hash(bytes).as_bytes());
    id
}

/// Local executor mirroring the sync-family `apply_ops` helper. Kept
/// here so this module is self-contained.
fn apply_ops(db: &SqlConnection, ops: &[WriteOp]) -> rusqlite::Result<()> {
    for op in ops {
        match op {
            WriteOp::InsertOrIgnore {
                table,
                columns,
                values,
            } => {
                let cols = columns.join(", ");
                let placeholders: Vec<String> =
                    (1..=values.len()).map(|i| format!("?{}", i)).collect();
                let sql = format!(
                    "INSERT OR IGNORE INTO {} ({}) VALUES ({})",
                    table,
                    cols,
                    placeholders.join(", ")
                );
                let bound: Vec<Box<dyn rusqlite::ToSql>> = values
                    .iter()
                    .map(|v| -> Box<dyn rusqlite::ToSql> {
                        match v {
                            SqlVal::Text(s) => Box::new(s.clone()),
                            SqlVal::Int(i) => Box::new(*i),
                            SqlVal::Blob(b) => Box::new(b.clone()),
                        }
                    })
                    .collect();
                let refs: Vec<&dyn rusqlite::ToSql> = bound.iter().map(|b| b.as_ref()).collect();
                db.execute(&sql, refs.as_slice())?;
            }
            WriteOp::Delete {
                table,
                where_clause,
            } => {
                let conds: Vec<String> = where_clause
                    .iter()
                    .enumerate()
                    .map(|(i, (col, _))| format!("{} = ?{}", col, i + 1))
                    .collect();
                let sql = format!("DELETE FROM {} WHERE {}", table, conds.join(" AND "));
                let bound: Vec<Box<dyn rusqlite::ToSql>> = where_clause
                    .iter()
                    .map(|(_, v)| -> Box<dyn rusqlite::ToSql> {
                        match v {
                            SqlVal::Text(s) => Box::new(s.clone()),
                            SqlVal::Int(i) => Box::new(*i),
                            SqlVal::Blob(b) => Box::new(b.clone()),
                        }
                    })
                    .collect();
                let refs: Vec<&dyn rusqlite::ToSql> = bound.iter().map(|b| b.as_ref()).collect();
                db.execute(&sql, refs.as_slice())?;
            }
        }
    }
    Ok(())
}
