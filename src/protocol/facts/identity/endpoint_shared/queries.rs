//! Read-only queries over shared endpoint membership.
//!
//! `endpoint_shared` rows are the identity facts other protocol families use
//! to decide whether a signer or peer belongs to a workspace. This module
//! exposes the projected peer list in deterministic display order. It should
//! stay side-effect free; endpoint authority is established by projection, not
//! by these lookups.

use crate::core::facts::FactId;
use crate::core::store::Store;

use super::rows::{decode_endpoint_shared_row, EndpointSharedRow, ENDPOINT_SHARED_ROWS};

pub fn peers_in_workspace(
    store: &Store,
    workspace_id: FactId,
) -> Result<Vec<EndpointSharedRow>, String> {
    let mut rows = store
        .table_rows_with_key_prefix(ENDPOINT_SHARED_ROWS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load endpoint peers: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_endpoint_shared_row(&key, &value))
        .collect::<Result<Vec<_>, _>>()?;
    rows.sort_by(|left, right| {
        left.device_name
            .cmp(&right.device_name)
            .then_with(|| left.endpoint_id.cmp(&right.endpoint_id))
    });
    Ok(rows)
}
