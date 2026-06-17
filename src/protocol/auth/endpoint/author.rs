//! Local endpoint fact construction and private capability access.
//!
//! `create_local_endpoint` and `endpoint_fact` build new local endpoint
//! material. `local_endpoint` reconstructs local private endpoint material for
//! command and handler capability boundaries that are already authorized to
//! use it; this is deliberately not in `queries.rs`, which exposes only
//! projected public state. Reactive paths share these constructors.

use crate::core::crypto;
use crate::core::facts::{Fact, FactScope};
use crate::core::store::Store;
use rusqlite::{params, OptionalExtension};

use super::encode;
use super::fact::EndpointFact;

pub fn create_local_endpoint() -> EndpointFact {
    let secret = crypto::random_x25519_private_key();
    let signing_secret = crypto::random_ed25519_private_key();
    EndpointFact {
        endpoint: crypto::x25519_public_key(&secret),
        secret,
        signing_public_key: crypto::ed25519_public_key(&signing_secret),
        signing_secret,
    }
}

pub fn endpoint_fact(created_at_ms: u64, endpoint: EndpointFact) -> Result<Fact, String> {
    Ok(Fact::new(
        FactScope::Local,
        created_at_ms,
        encode::encode_fact(&endpoint)?,
    ))
}

// ---------------------------------------------------------------------------
// Local endpoint private capability access.
//
// Private endpoint material is reconstructed for command and handler capability
// boundaries that are already authorized to use it.
// ---------------------------------------------------------------------------

pub fn local_endpoint(store: &Store) -> Result<Option<EndpointFact>, String> {
    let endpoint = store
        .conn()
        .query_row(
            "SELECT endpoint_id, secret, signing_public_key, signing_secret
             FROM local_endpoint_rows
             WHERE local_key = ?1
             LIMIT 1",
            params![super::LOCAL_KEY],
            decode_local_endpoint,
        )
        .optional()
        .map_err(|err| format!("load local endpoint: {err}"))?;

    if let Some(endpoint) = endpoint {
        if crypto::x25519_public_key(&endpoint.secret) != endpoint.endpoint {
            return Err("stored endpoint does not match local endpoint secret".to_string());
        }
        if crypto::ed25519_public_key(&endpoint.signing_secret) != endpoint.signing_public_key {
            return Err(
                "stored endpoint signing key does not match local signing secret".to_string(),
            );
        }
        Ok(Some(endpoint))
    } else {
        Ok(None)
    }
}

fn decode_local_endpoint(row: &rusqlite::Row<'_>) -> rusqlite::Result<EndpointFact> {
    Ok(EndpointFact {
        endpoint: id32(&row.get::<_, Vec<u8>>(0)?, "local endpoint")?,
        secret: id32(&row.get::<_, Vec<u8>>(1)?, "local endpoint secret")?,
        signing_public_key: id32(
            &row.get::<_, Vec<u8>>(2)?,
            "local endpoint signing public key",
        )?,
        signing_secret: id32(&row.get::<_, Vec<u8>>(3)?, "local endpoint signing secret")?,
    })
}

fn id32(value: &[u8], label: &str) -> rusqlite::Result<[u8; 32]> {
    value
        .try_into()
        .map_err(|_| rusqlite::Error::InvalidParameterName(format!("{label} row must be 32 bytes")))
}
