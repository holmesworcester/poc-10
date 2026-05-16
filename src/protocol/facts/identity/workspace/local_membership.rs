//! Cross-module workspace identity read models.
//!
//! These helpers compose already-projected rows for user-facing selection and
//! display. They are intentionally separate from leaf-module `queries.rs`
//! files, which should only read their own rows.

use crate::core::facts::FactId;
use crate::core::store::Store;
use crate::protocol::facts::identity;
use crate::protocol::facts::identity::endpoint_shared;

use endpoint_shared::rows::EndpointSharedRow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalWorkspaceMembership {
    pub workspace_id: FactId,
    pub workspace_name: String,
    pub endpoint_shared: EndpointSharedRow,
}

pub fn local_memberships(store: &Store) -> Result<Vec<LocalWorkspaceMembership>, String> {
    let Some(local_endpoint) = local_endpoint_id(store)? else {
        return Ok(Vec::new());
    };
    let mut rows = store
        .table_rows(endpoint_shared::rows::ENDPOINT_SHARED_ROWS)
        .map_err(|err| format!("load endpoint memberships: {err}"))?
        .into_iter()
        .map(|(key, value)| endpoint_shared::rows::decode_endpoint_shared_row(&key, &value))
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
            identity::endpoint::rows::LOCAL_ENDPOINT_ROWS,
            identity::endpoint::rows::LOCAL_KEY,
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
        .table_row(super::rows::WORKSPACE_ROWS, &workspace_id)
        .map_err(|err| format!("load workspace row: {err}"))?
        .map(|value| super::rows::decode_workspace_row(&workspace_id, &value).map(|row| row.name))
        .transpose()
}
