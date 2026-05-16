//! Read-only projected endpoint membership lookups.

use crate::core::facts::FactId;
use crate::core::store::Store;
use crate::event_modules::{identity_endpoint, identity_workspace};

use super::rows::{decode_endpoint_shared_row, EndpointSharedRow, ENDPOINT_SHARED_ROWS};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalWorkspaceMembership {
    pub workspace_id: FactId,
    pub workspace_name: String,
    pub endpoint_shared: EndpointSharedRow,
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

pub fn local_memberships(store: &Store) -> Result<Vec<LocalWorkspaceMembership>, String> {
    let Some(local_endpoint) = local_endpoint_id(store)? else {
        return Ok(Vec::new());
    };
    let mut rows = store
        .table_rows(ENDPOINT_SHARED_ROWS)
        .map_err(|err| format!("load endpoint memberships: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_endpoint_shared_row(&key, &value))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|row| row.endpoint_id == local_endpoint)
        .filter_map(|row| match workspace_name(store, row.workspace_id) {
            Ok(Some(name)) => Some(Ok(LocalWorkspaceMembership {
                workspace_id: row.workspace_id,
                workspace_name: name,
                endpoint_shared: row,
            })),
            Ok(None) => None,
            Err(err) => Some(Err(err)),
        })
        .collect::<Result<Vec<_>, String>>()?;
    rows.sort_by(|left, right| {
        left.workspace_name
            .cmp(&right.workspace_name)
            .then_with(|| left.workspace_id.cmp(&right.workspace_id))
    });
    Ok(rows)
}

pub fn local_membership(
    store: &Store,
    workspace_id: FactId,
) -> Result<Option<EndpointSharedRow>, String> {
    Ok(local_memberships(store)?
        .into_iter()
        .find(|membership| membership.workspace_id == workspace_id)
        .map(|membership| membership.endpoint_shared))
}

fn local_endpoint_id(store: &Store) -> Result<Option<FactId>, String> {
    store
        .table_row(
            identity_endpoint::rows::LOCAL_ENDPOINT_ROWS,
            identity_endpoint::rows::LOCAL_KEY,
        )
        .map_err(|err| format!("load local endpoint: {err}"))?
        .map(|value| {
            value
                .as_slice()
                .try_into()
                .map_err(|_| "local endpoint row must be 32 bytes".to_string())
        })
        .transpose()
}

fn workspace_name(store: &Store, workspace_id: FactId) -> Result<Option<String>, String> {
    store
        .table_row(identity_workspace::rows::WORKSPACE_ROWS, &workspace_id)
        .map_err(|err| format!("load workspace row: {err}"))?
        .map(|value| {
            identity_workspace::rows::decode_workspace_row(&workspace_id, &value)
                .map(|row| row.name)
        })
        .transpose()
}
