//! Local connection handshake secret family.
//!
//! An ephemeral secret is private X25519 material created for one handshake
//! leg. It exists as a local fact so request and response projectors can prove
//! that the public key they reference is backed by local private material, while
//! the secret bytes never become shared protocol state.
//!
//! Projection validates the keypair, writes a local row keyed by the secret
//! fact id, and publishes exact local context for the matching request or
//! response. Change this family when handshake secret bytes, row storage, or
//! context offers change; request and connection facts own how the secret
//! is consumed.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;

use crate::core::crypto::{X25519PrivateKey, X25519PublicKey};
use crate::core::db::{Db, TableInsert, TableName, TypedTableSchema, Value};
use crate::core::facts::FactId;
use rusqlite::{params, OptionalExtension, Row};

use fact::EndpointId;

/// Durable rows for local connection ephemeral secrets, keyed by the secret
/// fact id. The value stores the owner endpoint, public key, private key, and
/// creation time so response construction can load the local handshake material
/// without re-decoding fact bytes.
pub const CONNECTION_EPHEMERAL_SECRET_ROWS: TableName =
    TableName::new("connection_ephemeral_secret_rows");

pub const CONNECTION_EPHEMERAL_SECRET_COLUMNS: &[&str] = &[
    "secret_id",
    "owner_endpoint",
    "ephemeral_private_key",
    "ephemeral_public_key",
    "created_at_ms",
];
pub const CONNECTION_EPHEMERAL_SECRET_KEY_COLUMNS: &[&str] = &["secret_id"];
pub const CONNECTION_EPHEMERAL_SECRET_TABLE: TypedTableSchema = TypedTableSchema {
    table: CONNECTION_EPHEMERAL_SECRET_ROWS,
    columns: CONNECTION_EPHEMERAL_SECRET_COLUMNS,
    key_columns: CONNECTION_EPHEMERAL_SECRET_KEY_COLUMNS,
};

pub fn connection_ephemeral_secret_key(secret_id: &FactId) -> Vec<u8> {
    secret_id.to_vec()
}

pub fn connection_ephemeral_secret_row(
    secret_id: FactId,
    fact: &fact::ConnectionEphemeralSecretFact,
) -> TableInsert {
    CONNECTION_EPHEMERAL_SECRET_TABLE.insert(vec![
        Value::Bytes(secret_id.to_vec()),
        Value::Bytes(fact.owner_endpoint.to_vec()),
        Value::Bytes(fact.ephemeral_private_key.to_vec()),
        Value::Bytes(fact.ephemeral_public_key.to_vec()),
        Value::U64(fact.created_at_ms),
    ])
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ConnectionEphemeralSecretFact, String> {
    project::decode::decode_fact(bytes)
}

/// Decoded local ephemeral-secret row.
///
/// Rows contain private material and are meaningful only inside the local store,
/// so this read stays in the family module (capability-bearing), not in the
/// public `queries.rs` read-model surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionEphemeralSecretRow {
    pub secret_id: FactId,
    pub owner_endpoint: EndpointId,
    pub ephemeral_private_key: X25519PrivateKey,
    pub ephemeral_public_key: X25519PublicKey,
    pub created_at_ms: u64,
}

pub fn decode_connection_ephemeral_secret_row(
    row: &Row<'_>,
) -> rusqlite::Result<ConnectionEphemeralSecretRow> {
    Ok(ConnectionEphemeralSecretRow {
        secret_id: row.get(0)?,
        owner_endpoint: row.get(1)?,
        ephemeral_private_key: row.get(2)?,
        ephemeral_public_key: row.get(3)?,
        created_at_ms: row.get::<_, i64>(4)? as u64,
    })
}

pub fn connection_ephemeral_secret_by_id(
    store: &Db,
    secret_id: FactId,
) -> Result<Option<ConnectionEphemeralSecretRow>, String> {
    store
        .conn()
        .query_row(
            "SELECT secret_id,
                    owner_endpoint,
                    ephemeral_private_key,
                    ephemeral_public_key,
                    created_at_ms
             FROM connection_ephemeral_secret_rows
             WHERE secret_id = ?1
             LIMIT 1",
            params![secret_id],
            decode_connection_ephemeral_secret_row,
        )
        .optional()
        .map_err(|err| format!("load ephemeral secret row: {err}"))
}

pub fn connection_ephemeral_secret_rows(
    store: &Db,
) -> Result<Vec<ConnectionEphemeralSecretRow>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT secret_id,
                    owner_endpoint,
                    ephemeral_private_key,
                    ephemeral_public_key,
                    created_at_ms
             FROM connection_ephemeral_secret_rows
             ORDER BY secret_id
             LIMIT ?1",
        )
        .map_err(|err| format!("load ephemeral secret rows: {err}"))?;
    let rows = stmt
        .query_map(
            params![crate::core::db::DEFAULT_QUERY_LIMIT as i64],
            decode_connection_ephemeral_secret_row,
        )
        .map_err(|err| format!("load ephemeral secret rows: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("decode ephemeral secret rows: {err}"))
}
