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

/// One endpoint's membership binding — the minimal typed interface other scopes
/// need to reason about cross-workspace membership without touching
/// `endpoint_shared` row internals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointMembership {
    pub workspace_id: FactId,
    pub endpoint_id: FactId,
    pub endpoint_shared_id: FactId,
}

/// Every projected endpoint membership across all workspaces, in deterministic
/// order. Other scopes use this to decide mutual membership without importing
/// `endpoint_shared` rows.
pub fn all_memberships(store: &Store) -> Result<Vec<EndpointMembership>, String> {
    let mut memberships = store
        .table_rows(ENDPOINT_SHARED_ROWS)
        .map_err(|err| format!("load endpoint memberships: {err}"))?
        .into_iter()
        .map(|(key, value)| {
            decode_endpoint_shared_row(&key, &value).map(|row| EndpointMembership {
                workspace_id: row.workspace_id,
                endpoint_id: row.endpoint_id,
                endpoint_shared_id: row.endpoint_shared_id,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    memberships.sort_by(|left, right| {
        left.workspace_id
            .cmp(&right.workspace_id)
            .then_with(|| left.endpoint_id.cmp(&right.endpoint_id))
    });
    Ok(memberships)
}

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
