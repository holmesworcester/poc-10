//! Projector for `IntroEvent`. Verifies the introducer's signature, then
//! writes one row per (intro, subject) pair into `intros`. Downstream the
//! connect-loop uses `intros` rows as dialing hints.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rusqlite::{params, Connection};

use super::event::IntroEvent;

#[derive(Debug)]
pub enum ProjectError {
    BadSignature,
    BadIntroducerKey,
    Sqlite(rusqlite::Error),
}

impl std::fmt::Display for ProjectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadSignature => write!(f, "intro signature did not verify"),
            Self::BadIntroducerKey => write!(f, "intro signed_by is not a valid ed25519 verifying key"),
            Self::Sqlite(e) => write!(f, "intro sqlite error: {}", e),
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
        CREATE TABLE IF NOT EXISTS intros (
            intro_id              BLOB NOT NULL,
            introducer_endpoint   BLOB NOT NULL,
            subject_endpoint_id   BLOB NOT NULL,
            other_subject_id      BLOB NOT NULL,
            ip                    BLOB NOT NULL,
            port                  INTEGER NOT NULL,
            created_at_ms         INTEGER NOT NULL,
            PRIMARY KEY (intro_id, subject_endpoint_id, ip, port)
        );
        CREATE INDEX IF NOT EXISTS idx_intros_by_subject
            ON intros (subject_endpoint_id, created_at_ms DESC);
        ",
    )?;
    Ok(())
}

/// Compute a deterministic intro_id from the event content (no canonical
/// hash machinery wired up yet for connection-event types). Hash signing
/// bytes plus signature so two intros from the same introducer with
/// different addresses produce different ids.
fn intro_id(ev: &IntroEvent) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"poc8-intro-id-v1");
    h.update(&ev.signing_bytes());
    h.update(&ev.signature);
    let out = h.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(out.as_bytes());
    id
}

pub fn project(db: &Connection, ev: &IntroEvent) -> Result<(), ProjectError> {
    ensure_schema(db)?;

    let vk = VerifyingKey::from_bytes(&ev.signed_by).map_err(|_| ProjectError::BadIntroducerKey)?;
    let sig = Signature::from_bytes(&ev.signature);
    vk.verify(&ev.signing_bytes(), &sig)
        .map_err(|_| ProjectError::BadSignature)?;

    let id = intro_id(ev);

    let mut stmt = db.prepare(
        "INSERT OR IGNORE INTO intros
            (intro_id, introducer_endpoint, subject_endpoint_id, other_subject_id,
             ip, port, created_at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )?;

    for a in &ev.addresses_a {
        stmt.execute(params![
            id.to_vec(),
            ev.signed_by.to_vec(),
            ev.subject_a_endpoint_id.to_vec(),
            ev.subject_b_endpoint_id.to_vec(),
            a.ip.to_vec(),
            a.port as i64,
            ev.created_at_ms as i64,
        ])?;
    }
    for a in &ev.addresses_b {
        stmt.execute(params![
            id.to_vec(),
            ev.signed_by.to_vec(),
            ev.subject_b_endpoint_id.to_vec(),
            ev.subject_a_endpoint_id.to_vec(),
            a.ip.to_vec(),
            a.port as i64,
            ev.created_at_ms as i64,
        ])?;
    }

    // For empty address-list intros (just a referral, no hint), write a
    // single sentinel row with port 0 / zero-ip per subject so the dialer can
    // still observe that an introduction occurred.
    if ev.addresses_a.is_empty() {
        stmt.execute(params![
            id.to_vec(),
            ev.signed_by.to_vec(),
            ev.subject_a_endpoint_id.to_vec(),
            ev.subject_b_endpoint_id.to_vec(),
            vec![0u8; 16],
            0i64,
            ev.created_at_ms as i64,
        ])?;
    }
    if ev.addresses_b.is_empty() {
        stmt.execute(params![
            id.to_vec(),
            ev.signed_by.to_vec(),
            ev.subject_b_endpoint_id.to_vec(),
            ev.subject_a_endpoint_id.to_vec(),
            vec![0u8; 16],
            0i64,
            ev.created_at_ms as i64,
        ])?;
    }

    Ok(())
}
