//! Projector for `ConnectionPrekeySharedEvent`.
//!
//! Verifies the owner endpoint's signature and dedup-inserts a row into
//! `connection_prekeys_shared`. Indexed by `endpoint_id` so `wrap_bootstrap`
//! can resolve a peer's freshest live shared prekey.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rusqlite::{params, Connection};

use super::event::ConnectionPrekeySharedEvent;

#[derive(Debug)]
pub enum ProjectError {
    BadSignature,
    BadOwnerKey,
    Sqlite(rusqlite::Error),
}

impl std::fmt::Display for ProjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSignature => write!(f, "connection_prekey_shared signature did not verify"),
            Self::BadOwnerKey => {
                write!(f, "connection_prekey_shared endpoint_id is not a valid ed25519 verifying key")
            }
            Self::Sqlite(e) => write!(f, "connection_prekey_shared sqlite error: {}", e),
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
        CREATE TABLE IF NOT EXISTS connection_prekeys_shared (
            prekey_id     BLOB PRIMARY KEY,
            endpoint_id   BLOB NOT NULL,
            public_key    BLOB NOT NULL,
            created_at_ms INTEGER NOT NULL,
            ttl_ms        INTEGER NOT NULL,
            signature     BLOB NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_connection_prekeys_shared_by_endpoint
            ON connection_prekeys_shared (endpoint_id, created_at_ms DESC);
        ",
    )?;
    Ok(())
}

pub fn project(db: &Connection, ev: &ConnectionPrekeySharedEvent) -> Result<(), ProjectError> {
    ensure_schema(db)?;

    let vk = VerifyingKey::from_bytes(&ev.endpoint_id).map_err(|_| ProjectError::BadOwnerKey)?;
    let sig = Signature::from_bytes(&ev.signature);
    vk.verify(&ev.signing_bytes(), &sig)
        .map_err(|_| ProjectError::BadSignature)?;

    db.execute(
        "INSERT OR IGNORE INTO connection_prekeys_shared
            (prekey_id, endpoint_id, public_key, created_at_ms, ttl_ms, signature)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            ev.prekey_id.to_vec(),
            ev.endpoint_id.to_vec(),
            ev.public_key.to_vec(),
            ev.created_at_ms as i64,
            ev.ttl_ms as i64,
            ev.signature.to_vec(),
        ],
    )?;
    Ok(())
}
