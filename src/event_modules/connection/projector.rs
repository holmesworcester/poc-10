//! `Connection` projector.
//!
//! The pipeline-facing pure projector lives in `registry_meta.rs`. This
//! module retains the legacy direct-DB `project` entrypoint (used by the
//! Phase 1 wrap/unwrap surfaces) and the schema setup. Both paths now do
//! real ed25519 signature verification before writing.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rusqlite::{params, Connection as SqlConnection};

use super::event::Connection;

#[derive(Debug)]
pub enum ConnectionProjectError {
    Sqlite(rusqlite::Error),
    BadSigner,
    BadSignature,
}

impl std::fmt::Display for ConnectionProjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "sqlite error: {}", e),
            Self::BadSigner => write!(f, "connection signer is not a valid ed25519 verifying key"),
            Self::BadSignature => write!(f, "connection signature did not verify"),
        }
    }
}

impl std::error::Error for ConnectionProjectError {}

impl From<rusqlite::Error> for ConnectionProjectError {
    fn from(e: rusqlite::Error) -> Self {
        ConnectionProjectError::Sqlite(e)
    }
}

/// Insert / refresh the `connections` row plus the
/// `connection_shared_workspaces` rows so `wrap`/`unwrap` can read them
/// back. Verifies the signer's ed25519 signature against
/// `Connection::signing_bytes()` before any write.
pub fn project(db: &SqlConnection, ev: &Connection) -> Result<(), ConnectionProjectError> {
    ensure_schema(db)?;
    verify_signature(ev)?;

    db.execute(
        "INSERT OR REPLACE INTO connections
            (endpoint_a, endpoint_b, signed_at_ms, signer, signature, created_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            ev.endpoint_a.to_vec(),
            ev.endpoint_b.to_vec(),
            ev.signed_at_ms as i64,
            ev.signer.to_vec(),
            ev.signature.to_vec(),
            ev.created_at_ms as i64,
        ],
    )?;

    // Canonical event id (Blake2b-256 of the full canonical wire bytes,
    // including the signature). This is the value other tables use to
    // reference this Connection event (events_canonical, blocked_by_event,
    // outbox, connection_shared_workspaces). Two Connection events with the
    // same (endpoint_a, endpoint_b, signed_at_ms) but different signatures
    // therefore get distinct connection_ids — they are distinct events.
    let connection_id = ev.canonical_event_id();
    db.execute(
        "DELETE FROM connection_shared_workspaces WHERE connection_id = ?1",
        params![connection_id.to_vec()],
    )?;
    let mut stmt = db.prepare(
        "INSERT OR IGNORE INTO connection_shared_workspaces (connection_id, workspace_id)
         VALUES (?1, ?2)",
    )?;
    for ws in &ev.shared_workspaces {
        stmt.execute(params![connection_id.to_vec(), ws.to_vec()])?;
    }
    Ok(())
}

/// Verify the signer's ed25519 signature over `Connection::signing_bytes()`.
pub fn verify_signature(ev: &Connection) -> Result<(), ConnectionProjectError> {
    let vk = VerifyingKey::from_bytes(&ev.signer)
        .map_err(|_| ConnectionProjectError::BadSigner)?;
    let sig = Signature::from_bytes(&ev.signature);
    vk.verify(&ev.signing_bytes(), &sig)
        .map_err(|_| ConnectionProjectError::BadSignature)
}

pub fn ensure_schema(conn: &SqlConnection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS connections (
            endpoint_a    BLOB NOT NULL,
            endpoint_b    BLOB NOT NULL,
            signed_at_ms  INTEGER NOT NULL,
            signer        BLOB NOT NULL,
            signature     BLOB NOT NULL,
            created_at_ms INTEGER NOT NULL,
            PRIMARY KEY (endpoint_a, endpoint_b, signed_at_ms)
        );
        CREATE TABLE IF NOT EXISTS connection_shared_workspaces (
            connection_id BLOB NOT NULL,
            workspace_id  BLOB NOT NULL,
            PRIMARY KEY (connection_id, workspace_id)
        );
        ",
    )?;
    Ok(())
}
