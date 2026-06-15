//! Read-only workspace projections.
//!
//! Query helpers are the only workspace module functions that inspect
//! projected row state directly. They never write, construct facts, project,
//! or dispatch intents.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::FactId;
use crate::core::row_schema::RowValue;
use crate::core::runtime::Runtime;
use crate::core::store::Store;
use crate::protocol::auth;
use crate::protocol::auth::endpoint_shared;
use crate::protocol::connection;
use crate::protocol::sync::shared_fact;

use super::fact::{WorkspaceId, WorkspacePublicKey, WORKSPACE_NAME_BYTES};
use endpoint_shared::queries::EndpointSharedRow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceRow {
    pub workspace_id: WorkspaceId,
    pub created_at_ms: u64,
    pub public_key: WorkspacePublicKey,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceSummary {
    pub workspace_id: FactId,
    pub created_at_ms: u64,
    pub public_key: Ed25519PublicKey,
    pub name: String,
}

pub fn list_workspaces(store: &Store) -> Result<Vec<WorkspaceSummary>, String> {
    let mut workspaces = Vec::new();
    for (key, value) in store
        .table_rows(super::WORKSPACE_ROWS)
        .map_err(|err| format!("read workspace rows: {err}"))?
    {
        let row = decode_workspace_row(&key, &value)?;
        workspaces.push(WorkspaceSummary {
            workspace_id: row.workspace_id,
            created_at_ms: row.created_at_ms,
            public_key: row.public_key,
            name: row.name,
        });
    }
    Ok(workspaces)
}

pub fn workspace_by_id(store: &Store, workspace_id: FactId) -> Result<WorkspaceSummary, String> {
    list_workspaces(store)?
        .into_iter()
        .find(|workspace| workspace.workspace_id == workspace_id)
        .ok_or_else(|| format!("workspace row not found for {}", hex_id(&workspace_id)))
}

pub fn count_workspaces(store: &Store) -> Result<usize, String> {
    store
        .table_row_count(super::WORKSPACE_ROWS)
        .map_err(|err| format!("count workspace rows: {err}"))
}

fn hex_id(id: &FactId) -> String {
    let mut out = String::with_capacity(64);
    for byte in id {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

// ---------------------------------------------------------------------------
// Cross-module workspace membership read models.
//
// These helpers compose already-projected rows for user-facing selection and
// display across the endpoint-shared and workspace tables.
// ---------------------------------------------------------------------------

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
        .table_rows(endpoint_shared::ENDPOINT_SHARED_ROWS)
        .map_err(|err| format!("load endpoint memberships: {err}"))?
        .into_iter()
        .map(|(key, value)| endpoint_shared::queries::decode_endpoint_shared_row(&key, &value))
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
            auth::endpoint::LOCAL_ENDPOINT_ROWS,
            auth::endpoint::LOCAL_KEY,
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
        .table_row(super::WORKSPACE_ROWS, &workspace_id)
        .map_err(|err| format!("load workspace row: {err}"))?
        .map(|value| decode_workspace_row(&workspace_id, &value).map(|row| row.name))
        .transpose()
}

// ---------------------------------------------------------------------------
// Product runtime count read model for the `count` CLI command.
//
// Composes protocol runtime state across facts, context projection,
// connections, and accepted invites for one user-facing diagnostic report.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeCountReport {
    pub workspace_rows: usize,
    pub facts: usize,
    pub sync_facts: usize,
    pub applied_facts: usize,
    pub pending_intents: usize,
    pub connections: usize,
    pub connection_facts: usize,
    pub invite_accepted: usize,
}

pub fn runtime_count_report(runtime: &Runtime) -> Result<RuntimeCountReport, String> {
    let workspace_rows = runtime
        .store()
        .table_row_count(super::WORKSPACE_ROWS)
        .map_err(|err| format!("count workspace rows: {err}"))?;
    let facts = runtime.facts().count();
    let sync_facts = shared_fact::sync_status(runtime.store())?.indexed_facts;
    let applied_facts = facts.saturating_sub(runtime.pending_fact_count());
    let pending_intents = runtime.pending_intent_count();
    let connections = runtime
        .store()
        .table_rows(connection::connection::CONNECTION_ROWS)
        .map_err(|err| format!("count connections: {err}"))?
        .len();
    let connection_requests = runtime
        .store()
        .table_rows(connection::request::CONNECTION_REQUEST_ROWS)
        .map_err(|err| format!("count connection requests: {err}"))?
        .len();
    let invite_accepted = runtime
        .store()
        .table_rows(auth::invite_accepted::INVITE_ACCEPTED_ROWS)
        .map_err(|err| format!("count invite accepted: {err}"))?
        .len();
    Ok(RuntimeCountReport {
        workspace_rows,
        facts,
        sync_facts,
        applied_facts,
        pending_intents,
        connections,
        connection_facts: connection_requests + connections,
        invite_accepted,
    })
}

pub(crate) fn decode_workspace_row(key: &[u8], value: &[u8]) -> Result<WorkspaceRow, String> {
    let key_fields = super::WORKSPACE_ROW_SCHEMA.decode_key(key)?;
    let value_fields = super::WORKSPACE_ROW_SCHEMA.decode_value(value)?;
    let workspace_id = bytes32_field(&key_fields[0], "workspace_id")?;
    let created_at_ms = u64_field(&value_fields[0], "created_at_ms")?;
    let public_key = bytes32_field(&value_fields[1], "public_key")?;
    let name = workspace_name_field(&value_fields[2])?;
    Ok(WorkspaceRow {
        workspace_id,
        created_at_ms,
        public_key,
        name,
    })
}

fn bytes32_field(value: &RowValue, name: &str) -> Result<[u8; 32], String> {
    let bytes = bytes_field(value, name)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| format!("{name} must be 32 bytes"))
}

fn bytes_field(value: &RowValue, name: &str) -> Result<Vec<u8>, String> {
    match value {
        RowValue::Bytes(bytes) => Ok(bytes.clone()),
        _ => Err(format!("{name} must be bytes")),
    }
}

fn u64_field(value: &RowValue, name: &str) -> Result<u64, String> {
    match value {
        RowValue::U64(value) => Ok(*value),
        _ => Err(format!("{name} must be u64")),
    }
}

fn workspace_name_field(value: &RowValue) -> Result<String, String> {
    let bytes = bytes_field(value, "name")?;
    let padded: [u8; WORKSPACE_NAME_BYTES] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "workspace name slot has wrong length".to_string())?;
    super::fact::WorkspaceName::from_padded(padded)
        .map(|name| name.to_string())
        .map_err(|err| format!("{err:?}"))
}
