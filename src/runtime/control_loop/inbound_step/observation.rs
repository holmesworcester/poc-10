//! Inbound observation accounting.
//!
//! `record_observation` upserts the per-(wire_id, connection, endpoint)
//! row in `inbound_observations` and reports whether a fresh row was
//! created. Used both by `handle_inbound_bytes` (dedupe path) and by the
//! transport bridge (which records observations directly when it
//! enqueues bytes for the dispatcher).

use rusqlite::{params, Connection};

use super::super::work_item::BlakeId;
use super::InboundOrigin;

pub fn record_observation(
    db: &Connection,
    wire_id: &BlakeId,
    origin: &InboundOrigin,
    now_ms: i64,
) -> rusqlite::Result<bool> {
    let remote = origin.remote_endpoint_id.map(|e| e.to_vec());
    let ip = origin.ip.clone();
    let port = origin.port.map(|p| p as i64);

    // Single round-trip UPSERT: the previous EXISTS-then-UPDATE-or-INSERT
    // ran two SQL statements per inbound frame, which dominated the chain
    // hot path at high frame rates.
    //
    // ON CONFLICT targets the expression-based unique index
    // `uq_inbound_observations_provenance` (declared in
    // control_loop_tables) which COALESCEs the nullable `connection_id`
    // and `remote_endpoint_id` columns to a sentinel zero-length blob.
    // SQLite treats NULL as distinct in plain PRIMARY KEY uniqueness, so
    // referring to the table-level PK in the ON CONFLICT clause silently
    // fails to merge "first observation" with subsequent ones whenever
    // either column is NULL — the case record_observation() actually
    // hits in production. The expression-based index sidesteps that.
    //
    // `last_insert_rowid()` only advances on a true INSERT — the UPSERT
    // update branch leaves it unchanged. That's our `observation_added`
    // signal without a second query.
    let last_rowid_before = db.last_insert_rowid();
    db.execute(
        "INSERT INTO inbound_observations
            (wire_id, connection_id, remote_endpoint_id, ip, port,
             first_seen_at_ms, last_seen_at_ms, seen_count)
         VALUES (?1, NULL, ?2, ?3, ?4, ?5, ?5, 1)
         ON CONFLICT (wire_id,
                      COALESCE(connection_id, x''),
                      COALESCE(remote_endpoint_id, x''))
         DO UPDATE SET
             last_seen_at_ms = ?5,
             seen_count      = seen_count + 1",
        params![wire_id.to_vec(), remote, ip, port, now_ms],
    )?;
    let last_rowid_after = db.last_insert_rowid();
    Ok(last_rowid_after != last_rowid_before)
}
