//! Read-only workspace projections.
//!
//! Query helpers are the only workspace module functions that inspect
//! projected row state directly. They never write, construct facts, project,
//! or dispatch intents.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::db::{Db, DEFAULT_QUERY_LIMIT};
use crate::core::facts::FactId;
use crate::core::runtime::Runtime;
use crate::core::schema::FACTS;
use crate::protocol::auth;
use crate::protocol::auth::endpoint_shared;
use crate::protocol::connection;
use crate::protocol::sync::shared_fact;
use rusqlite::{params, OptionalExtension, Row};

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

pub fn list_workspaces(store: &Db) -> Result<Vec<WorkspaceSummary>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT workspace_id, created_at_ms, public_key, name
             FROM workspace_rows
             ORDER BY workspace_id
             LIMIT ?1",
        )
        .map_err(|err| format!("read workspace rows: {err}"))?;
    let rows = stmt
        .query_map(params![DEFAULT_QUERY_LIMIT as i64], decode_workspace_row)
        .map_err(|err| format!("read workspace rows: {err}"))?;
    rows.map(|row| {
        row.map(|row| WorkspaceSummary {
            workspace_id: row.workspace_id,
            created_at_ms: row.created_at_ms,
            public_key: row.public_key,
            name: row.name,
        })
    })
    .collect::<rusqlite::Result<Vec<_>>>()
    .map_err(|err| format!("decode workspace rows: {err}"))
}

pub fn workspace_by_id(store: &Db, workspace_id: FactId) -> Result<WorkspaceSummary, String> {
    let row = store
        .conn()
        .query_row(
            "SELECT workspace_id, created_at_ms, public_key, name
             FROM workspace_rows
             WHERE workspace_id = ?1
             LIMIT 1",
            params![workspace_id],
            decode_workspace_row,
        )
        .optional()
        .map_err(|err| format!("read workspace row: {err}"))?
        .ok_or_else(|| format!("workspace row not found for {}", hex_id(&workspace_id)))?;
    Ok(WorkspaceSummary {
        workspace_id: row.workspace_id,
        created_at_ms: row.created_at_ms,
        public_key: row.public_key,
        name: row.name,
    })
}

pub fn count_workspaces(store: &Db) -> Result<usize, String> {
    store
        .conn()
        .query_row("SELECT COUNT(*) FROM workspace_rows", [], |row| {
            row.get::<_, i64>(0).map(|count| count as usize)
        })
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

pub fn local_memberships(store: &Db) -> Result<Vec<LocalWorkspaceMembership>, String> {
    let Some(local_endpoint) = local_endpoint_id(store)? else {
        return Ok(Vec::new());
    };
    let mut rows = Vec::new();
    for workspace in list_workspaces(store)? {
        let Some(endpoint_shared) =
            endpoint_shared::queries::peers_in_workspace(store, workspace.workspace_id)?
                .into_iter()
                .find(|row| row.endpoint_id == local_endpoint)
        else {
            continue;
        };
        rows.push(LocalWorkspaceMembership {
            workspace_id: workspace.workspace_id,
            workspace_name: workspace.name,
            endpoint_shared,
        });
    }
    rows.sort_by(|left, right| {
        left.workspace_name
            .cmp(&right.workspace_name)
            .then_with(|| left.workspace_id.cmp(&right.workspace_id))
    });
    Ok(rows)
}

pub fn local_membership(
    store: &Db,
    workspace_id: FactId,
) -> Result<Option<EndpointSharedRow>, String> {
    let Some(local_endpoint) = local_endpoint_id(store)? else {
        return Ok(None);
    };
    Ok(
        endpoint_shared::queries::peers_in_workspace(store, workspace_id)?
            .into_iter()
            .find(|membership| membership.endpoint_id == local_endpoint),
    )
}

fn local_endpoint_id(store: &Db) -> Result<Option<FactId>, String> {
    auth::endpoint::queries::local_endpoint_public(store).map(|row| row.map(|row| row.endpoint))
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
        .db()
        .table_row_count(super::WORKSPACE_ROWS)
        .map_err(|err| format!("count workspace rows: {err}"))?;
    let facts = runtime
        .db()
        .table_row_count(FACTS)
        .map_err(|err| format!("count retained facts: {err}"))?;
    let sync_facts = shared_fact::sync_status(runtime.db())?.indexed_facts;
    let applied_facts = facts.saturating_sub(runtime.pending_fact_count());
    let pending_intents = runtime.pending_intent_count();
    let connections = runtime
        .db()
        .table_row_count(connection::connection::CONNECTION_ROWS)
        .map_err(|err| format!("count connections: {err}"))?;
    let connection_requests = runtime
        .db()
        .table_row_count(connection::request::CONNECTION_REQUEST_ROWS)
        .map_err(|err| format!("count connection requests: {err}"))?;
    let invite_accepted = runtime
        .db()
        .table_row_count(auth::invite_accepted::INVITE_ACCEPTED_ROWS)
        .map_err(|err| format!("count invite accepted: {err}"))?;
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

pub(crate) fn decode_workspace_row(row: &Row<'_>) -> rusqlite::Result<WorkspaceRow> {
    let bytes: Vec<u8> = row.get(3)?;
    let padded: [u8; WORKSPACE_NAME_BYTES] = bytes.as_slice().try_into().map_err(|_| {
        rusqlite::Error::InvalidParameterName("workspace name slot has wrong length".to_string())
    })?;
    let name = super::fact::WorkspaceName::from_padded(padded)
        .map(|name| name.to_string())
        .map_err(|err| rusqlite::Error::InvalidParameterName(format!("{err:?}")))?;
    Ok(WorkspaceRow {
        workspace_id: row.get(0)?,
        created_at_ms: row.get::<_, i64>(1)? as u64,
        public_key: row.get(2)?,
        name,
    })
}
