//! Projector for `SelfAddressEvent`.
//!
//! Verifies the endpoint's self-signature, then upserts a row into
//! `self_addresses` keyed by `(endpoint_id, ip, port)`. The `signed_by`
//! field must match `endpoint_id` (an endpoint can only claim its own
//! address); otherwise the event is rejected.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rusqlite::{params, Connection};

use super::event::SelfAddressEvent;

#[derive(Debug)]
pub enum ProjectError {
    BadSignature,
    BadEndpointKey,
    SignerMismatch,
    Sqlite(rusqlite::Error),
}

impl std::fmt::Display for ProjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSignature => write!(f, "self_address signature did not verify"),
            Self::BadEndpointKey => write!(f, "self_address endpoint_id is not a valid ed25519 verifying key"),
            Self::SignerMismatch => write!(f, "self_address signed_by must equal endpoint_id"),
            Self::Sqlite(e) => write!(f, "self_address sqlite error: {}", e),
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
        CREATE TABLE IF NOT EXISTS self_addresses (
            endpoint_id   BLOB NOT NULL,
            ip            BLOB NOT NULL,
            port          INTEGER NOT NULL,
            created_at_ms INTEGER NOT NULL,
            ttl_ms        INTEGER NOT NULL,
            signed_by     BLOB NOT NULL,
            signature     BLOB NOT NULL,
            PRIMARY KEY (endpoint_id, ip, port)
        );
        CREATE INDEX IF NOT EXISTS idx_self_addresses_by_endpoint
            ON self_addresses (endpoint_id, created_at_ms DESC);
        ",
    )?;
    Ok(())
}

pub fn project(db: &Connection, ev: &SelfAddressEvent) -> Result<(), ProjectError> {
    ensure_schema(db)?;

    if ev.signed_by != ev.endpoint_id {
        return Err(ProjectError::SignerMismatch);
    }
    let vk = VerifyingKey::from_bytes(&ev.endpoint_id).map_err(|_| ProjectError::BadEndpointKey)?;
    let sig = Signature::from_bytes(&ev.signature);
    vk.verify(&ev.signing_bytes(), &sig)
        .map_err(|_| ProjectError::BadSignature)?;

    db.execute(
        "INSERT OR REPLACE INTO self_addresses
            (endpoint_id, ip, port, created_at_ms, ttl_ms, signed_by, signature)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            ev.endpoint_id.to_vec(),
            ev.ip.to_vec(),
            ev.port as i64,
            ev.created_at_ms as i64,
            ev.ttl_ms as i64,
            ev.signed_by.to_vec(),
            ev.signature.to_vec(),
        ],
    )?;
    Ok(())
}
