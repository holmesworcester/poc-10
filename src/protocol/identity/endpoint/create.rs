//! Local endpoint fact construction and private capability access.
//!
//! `create_local_endpoint` and `endpoint_fact` build new local endpoint
//! material. `local_endpoint` reconstructs local private endpoint material for
//! command and handler capability boundaries that are already authorized to
//! use it; this is deliberately not in `queries.rs`, which exposes only
//! projected public state. Reactive paths share these constructors.

use crate::core::crypto;
use crate::core::fact_store::persisted_facts;
use crate::core::facts::{Fact, FactScope};
use crate::core::store::Store;

use super::fact::EndpointFact;
use super::{layout, rows};

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
        layout::encode_fact(&endpoint)?,
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
        .table_row(rows::LOCAL_ENDPOINT_ROWS, rows::LOCAL_KEY)
        .map_err(|err| format!("load local endpoint: {err}"))?;
    let secret = store
        .table_row(rows::LOCAL_ENDPOINT_SECRET_ROWS, rows::LOCAL_KEY)
        .map_err(|err| format!("load local endpoint secret: {err}"))?;
    let signing_public_key = store
        .table_row(
            rows::LOCAL_ENDPOINT_SIGNING_PUBLIC_KEY_ROWS,
            rows::LOCAL_KEY,
        )
        .map_err(|err| format!("load local endpoint signing public key: {err}"))?;
    let signing_secret = store
        .table_row(rows::LOCAL_ENDPOINT_SIGNING_SECRET_ROWS, rows::LOCAL_KEY)
        .map_err(|err| format!("load local endpoint signing secret: {err}"))?;

    match (endpoint, secret, signing_public_key, signing_secret) {
        (None, None, None, None) => unprojected_local_endpoint(store),
        (Some(endpoint), Some(secret), Some(signing_public_key), Some(signing_secret)) => {
            let endpoint = id32(&endpoint, "local endpoint")?;
            let secret = id32(&secret, "local endpoint secret")?;
            let signing_public_key =
                id32(&signing_public_key, "local endpoint signing public key")?;
            let signing_secret = id32(&signing_secret, "local endpoint signing secret")?;
            if crypto::x25519_public_key(&secret) != endpoint {
                return Err("stored endpoint does not match local endpoint secret".to_string());
            }
            if crypto::ed25519_public_key(&signing_secret) != signing_public_key {
                return Err(
                    "stored endpoint signing key does not match local signing secret".to_string(),
                );
            }
            Ok(Some(EndpointFact {
                endpoint,
                secret,
                signing_public_key,
                signing_secret,
            }))
        }
        (None, _, _, _) => Err("local endpoint public key is missing".to_string()),
        (_, None, _, _) => Err("local endpoint secret is missing".to_string()),
        (_, _, None, _) => Err("local endpoint signing public key is missing".to_string()),
        (_, _, _, None) => Err("local endpoint signing secret is missing".to_string()),
    }
}

fn unprojected_local_endpoint(store: &Store) -> Result<Option<EndpointFact>, String> {
    let mut endpoints = persisted_facts(store)?
        .into_iter()
        .filter(|fact| fact.scope == FactScope::Local)
        .filter_map(|fact| {
            layout::decode_fact(fact.body())
                .ok()
                .map(|endpoint| (fact.timestamp, fact.id, endpoint))
        })
        .collect::<Vec<_>>();
    endpoints.sort_by_key(|(timestamp, id, _)| (*timestamp, *id));
    Ok(endpoints
        .into_iter()
        .map(|(_, _, endpoint)| endpoint)
        .next())
}

fn id32(value: &[u8], label: &str) -> Result<[u8; 32], String> {
    value
        .try_into()
        .map_err(|_| format!("{label} row must be 32 bytes"))
}
