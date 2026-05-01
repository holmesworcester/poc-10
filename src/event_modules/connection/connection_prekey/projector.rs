//! Projector for `ConnectionPrekeyEvent`.
//!
//! Verifies the owner's signature, then upserts a row into
//! `connection_prekeys` keyed by `prekey_id`. The `endpoint_id` column is
//! indexed so jobs can pull the freshest live prekey for a given local
//! endpoint.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rusqlite::{params, Connection};

use super::event::ConnectionPrekeyEvent;

#[derive(Debug)]
pub enum ProjectError {
    BadSignature,
    BadOwnerKey,
    Sqlite(rusqlite::Error),
}

impl std::fmt::Display for ProjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSignature => write!(f, "connection_prekey signature did not verify"),
            Self::BadOwnerKey => write!(f, "connection_prekey endpoint_id is not a valid ed25519 verifying key"),
            Self::Sqlite(e) => write!(f, "connection_prekey sqlite error: {}", e),
        }
    }
}

impl std::error::Error for ProjectError {}

impl From<rusqlite::Error> for ProjectError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS connection_prekeys (
            prekey_id     BLOB PRIMARY KEY,
            endpoint_id   BLOB NOT NULL,
            private_key   BLOB NOT NULL,
            public_key    BLOB NOT NULL,
            created_at_ms INTEGER NOT NULL,
            ttl_ms        INTEGER NOT NULL,
            signature     BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_connection_prekeys_by_endpoint
            ON connection_prekeys (endpoint_id, created_at_ms DESC);
        ",
    )?;
    Ok(())
}

/// Verify the owner's signature, then insert (or replace) the prekey row.
pub fn project(db: &Connection, ev: &ConnectionPrekeyEvent) -> Result<(), ProjectError> {
    ensure_schema(db)?;

    // The endpoint_id is the ed25519 verifying-key bytes of the owner.
    let vk = VerifyingKey::from_bytes(&ev.endpoint_id).map_err(|_| ProjectError::BadOwnerKey)?;
    let sig = Signature::from_bytes(&ev.signature);
    vk.verify(&ev.signing_bytes(), &sig)
        .map_err(|_| ProjectError::BadSignature)?;

    db.execute(
        "INSERT OR REPLACE INTO connection_prekeys
            (prekey_id, endpoint_id, private_key, public_key, created_at_ms, ttl_ms, signature)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            ev.prekey_id.to_vec(),
            ev.endpoint_id.to_vec(),
            ev.private_key.to_vec(),
            ev.public_key.to_vec(),
            ev.created_at_ms as i64,
            ev.ttl_ms as i64,
            ev.signature.to_vec(),
        ],
    )?;
    Ok(())
}
