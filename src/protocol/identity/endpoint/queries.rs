//! Read-only local endpoint public-state lookups.
//!
//! Private endpoint material is not query state. Commands and handlers that
//! need local private keys use the capability helper in `commands.rs`; display
//! and selection code use this module.

use crate::core::facts::FactId;
use crate::core::store::Store;

use super::rows;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalEndpointPublic {
    pub endpoint: FactId,
    pub signing_public_key: [u8; 32],
}

pub fn local_endpoint_public(store: &Store) -> Result<Option<LocalEndpointPublic>, String> {
    let endpoint = store
        .table_row(rows::LOCAL_ENDPOINT_ROWS, rows::LOCAL_KEY)
        .map_err(|err| format!("load local endpoint: {err}"))?;
    let signing_public_key = store
        .table_row(
            rows::LOCAL_ENDPOINT_SIGNING_PUBLIC_KEY_ROWS,
            rows::LOCAL_KEY,
        )
        .map_err(|err| format!("load local endpoint signing public key: {err}"))?;

    match (endpoint, signing_public_key) {
        (None, None) => Ok(None),
        (Some(endpoint), Some(signing_public_key)) => {
            let endpoint = id32(&endpoint, "local endpoint")?;
            let signing_public_key =
                id32(&signing_public_key, "local endpoint signing public key")?;
            Ok(Some(LocalEndpointPublic {
                endpoint,
                signing_public_key,
            }))
        }
        (None, Some(_)) => Err("local endpoint public key is missing".to_string()),
        (Some(_), None) => Err("local endpoint signing public key is missing".to_string()),
    }
}

fn id32(value: &[u8], label: &str) -> Result<[u8; 32], String> {
    value
        .try_into()
        .map_err(|_| format!("{label} row must be 32 bytes"))
}
