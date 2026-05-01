use super::super::ParsedEvent;
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS tenants (
            event_id TEXT NOT NULL PRIMARY KEY,
            public_key BLOB NOT NULL,
            peer_id TEXT NOT NULL,
            created_at INTEGER NOT NULL
        );
        ",
    )?;
    Ok(())
}

pub fn project_pure(
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let e = match parsed {
        ParsedEvent::Tenant(v) => v,
        _ => return ProjectorResult::reject("not a tenant event".to_string()),
    };
    // Stage 3.5 round-9 step 3 (plan.md): `tenants` is keyed by
    // `event_id` alone — the table is an endpoint singleton (one
    // local-tenant root per DB). `recorded_by` was dropped from the PK
    // and the projection now writes a flat row.
    let peer_id = hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
        &e.public_key,
    ));

    ProjectorResult::valid(vec![WriteOp::InsertOrIgnore {
        table: "tenants",
        columns: vec!["event_id", "public_key", "peer_id", "created_at"],
        values: vec![
            SqlVal::Text(event_id_b64.to_string()),
            SqlVal::Blob(e.public_key.to_vec()),
            SqlVal::Text(peer_id),
            SqlVal::Int(e.created_at_ms as i64),
        ],
    }])
}
