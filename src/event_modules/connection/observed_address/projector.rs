//! Projector for `ObservedAddressEvent`.
//!
//! Verifies the observer endpoint's signature, then upserts a row into
//! `observed_addresses` keyed by (observer, subject, ip, port). TTL is
//! tracked alongside the row so callers can filter expired observations.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rusqlite::{params, Connection};

use super::event::ObservedAddressEvent;

#[derive(Debug)]
pub enum ProjectError {
    BadSignature,
    BadObserverKey,
    Sqlite(rusqlite::Error),
}

impl std::fmt::Display for ProjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSignature => write!(f, "observed_address signature did not verify"),
            Self::BadObserverKey => write!(f, "observed_address signed_by is not a valid ed25519 verifying key"),
            Self::Sqlite(e) => write!(f, "observed_address sqlite error: {}", e),
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
        CREATE TABLE IF NOT EXISTS observed_addresses (
            observer_endpoint_id BLOB NOT NULL,
            subject_endpoint_id  BLOB NOT NULL,
            ip                   BLOB NOT NULL,
            port                 INTEGER NOT NULL,
            observed_at_ms       INTEGER NOT NULL,
            ttl_ms               INTEGER NOT NULL,
            signed_by            BLOB NOT NULL,
            signature            BLOB NOT NULL,
            PRIMARY KEY (observer_endpoint_id, subject_endpoint_id, ip, port)
        );
        CREATE INDEX IF NOT EXISTS idx_observed_addresses_by_subject
            ON observed_addresses (subject_endpoint_id, observed_at_ms DESC);
        ",
    )?;
    Ok(())
}

pub fn project(db: &Connection, ev: &ObservedAddressEvent) -> Result<(), ProjectError> {
    ensure_schema(db)?;

    let vk = VerifyingKey::from_bytes(&ev.signed_by).map_err(|_| ProjectError::BadObserverKey)?;
    let sig = Signature::from_bytes(&ev.signature);
    vk.verify(&ev.signing_bytes(), &sig)
        .map_err(|_| ProjectError::BadSignature)?;

    db.execute(
        "INSERT OR REPLACE INTO observed_addresses
            (observer_endpoint_id, subject_endpoint_id, ip, port,
             observed_at_ms, ttl_ms, signed_by, signature)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            ev.observer_endpoint_id.to_vec(),
            ev.subject_endpoint_id.to_vec(),
            ev.ip.to_vec(),
            ev.port as i64,
            ev.observed_at_ms as i64,
            ev.ttl_ms as i64,
            ev.signed_by.to_vec(),
            ev.signature.to_vec(),
        ],
    )?;
    Ok(())
}
