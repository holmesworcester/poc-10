//! Read-only local endpoint public-state lookups.
//!
//! Private endpoint material is not query state. Commands and handlers that
//! need local private keys use the capability helper in `api.rs`; display
//! and selection code use this module.

use crate::core::db::Db;
use crate::core::facts::FactId;
use rusqlite::{params, OptionalExtension};

use super::LOCAL_KEY;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalEndpointPublic {
    pub endpoint: FactId,
    pub signing_public_key: [u8; 32],
}

pub fn local_endpoint_public(store: &Db) -> Result<Option<LocalEndpointPublic>, String> {
    store
        .conn()
        .query_row(
            "SELECT endpoint_id, signing_public_key
             FROM local_endpoint_rows
             WHERE local_key = ?1
             LIMIT 1",
            params![LOCAL_KEY],
            |row| {
                let endpoint = id32(&row.get::<_, Vec<u8>>(0)?, "local endpoint")?;
                let signing_public_key = id32(
                    &row.get::<_, Vec<u8>>(1)?,
                    "local endpoint signing public key",
                )?;
                Ok(LocalEndpointPublic {
                    endpoint,
                    signing_public_key,
                })
            },
        )
        .optional()
        .map_err(|err| format!("load local endpoint: {err}"))
}

fn id32(value: &[u8], label: &str) -> rusqlite::Result<[u8; 32]> {
    value
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidParameterName(format!("{label} row must be 32 bytes")))
}
