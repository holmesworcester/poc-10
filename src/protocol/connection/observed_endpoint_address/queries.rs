//! Observed endpoint-address lookups.
//!
//! Connection-maintenance code asks here for a known endpoint's reachable address.
//! This reads only the connection-owned learned-address rows; it never reads
//! auth-owned or endpoint-owned tables.

use std::net::SocketAddr;

use crate::core::facts::FactId;
use crate::core::store::Store;

use super::rows::{decode_observed_endpoint_address_row, observed_endpoint_address_key, CONNECTION_OBSERVED_ENDPOINT_ADDRESS_ROWS};

/// The last reachable listen address learned for `endpoint_id`, if any.
pub fn observed_endpoint_address(store: &Store, endpoint_id: &FactId) -> Result<Option<SocketAddr>, String> {
    let Some(value) = store
        .table_row(CONNECTION_OBSERVED_ENDPOINT_ADDRESS_ROWS, &observed_endpoint_address_key(endpoint_id))
        .map_err(|err| format!("load endpoint address: {err}"))?
    else {
        return Ok(None);
    };
    let (_, address) = decode_observed_endpoint_address_row(&observed_endpoint_address_key(endpoint_id), &value)?;
    Ok(Some(address))
}
