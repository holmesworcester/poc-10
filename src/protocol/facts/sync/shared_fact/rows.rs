//! Durable sync shareable-fact index rows and queries.

use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::store::{Store, TableName, TableRow};
use crate::core::wake_loop;
use crate::protocol::facts::{connection, identity};
use std::collections::BTreeSet;

pub const SHAREABLE_FACT_ROWS: TableName = TableName::new("sync_shareable_fact_rows");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareableFactRow {
    pub workspace_id: FactId,
    pub fact_id: FactId,
    pub timestamp_ms: u64,
}

pub fn shareable_fact_row(row: ShareableFactRow) -> TableRow {
    let mut value = Vec::with_capacity(9);
    value.push(1);
    value.extend_from_slice(&row.timestamp_ms.to_be_bytes());
    TableRow {
        table: SHAREABLE_FACT_ROWS,
        key: shareable_fact_key(row.workspace_id, row.fact_id),
        value,
    }
}

pub fn decode_shareable_fact_row(key: &[u8], value: &[u8]) -> Result<ShareableFactRow, String> {
    if key.len() != 64 {
        return Err("shareable fact key must be workspace id plus fact id".to_string());
    }
    if value.len() != 9 || value[0] != 1 {
        return Err("invalid shareable fact row value".to_string());
    }
    Ok(ShareableFactRow {
        workspace_id: key[..32].try_into().unwrap(),
        fact_id: key[32..64].try_into().unwrap(),
        timestamp_ms: u64::from_be_bytes(value[1..9].try_into().unwrap()),
    })
}

fn shareable_fact_key(workspace_id: FactId, fact_id: FactId) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&workspace_id);
    key.extend_from_slice(&fact_id);
    key
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStatus {
    pub indexed_facts: usize,
    pub root_count: u64,
    pub root_fingerprint: [u8; 32],
    pub pending_purges: usize,
}

pub fn record_shareable_fact(
    store: &Store,
    workspace_id: FactId,
    fact: &Fact,
    timestamp_ms: u64,
) -> Result<(), String> {
    if fact.timestamp != timestamp_ms {
        return Err("share_fact_with_workspace timestamp does not match fact".to_string());
    }
    match &fact.scope {
        FactScope::Scoped { kind, id } if kind.as_str() == "workspace" => {
            if id != &workspace_id {
                return Err("share_fact_with_workspace scope does not match workspace".to_string());
            }
        }
        FactScope::Global => {}
        _ => {
            return Err(
                "share_fact_with_workspace requires a workspace-scoped or global fact".to_string(),
            );
        }
    }
    store
        .insert_table_rows(vec![shareable_fact_row(ShareableFactRow {
            workspace_id,
            fact_id: fact.id,
            timestamp_ms,
        })])
        .map(|_| ())
        .map_err(|err| format!("record shareable fact row: {err}"))
}

pub fn sync_status(store: &Store) -> Result<SyncStatus, String> {
    let mut facts = Vec::new();
    for row in shareable_fact_rows(store)? {
        let Some(fact) = fact_for_shareable_row(store, &row)? else {
            continue;
        };
        facts.push(fact);
    }
    facts.sort_by_key(|fact| (fact.timestamp, fact.id));
    let mut fingerprint = [0u8; 32];
    for fact in &facts {
        let digest = sync_fingerprint(fact);
        for (dst, src) in fingerprint.iter_mut().zip(digest) {
            *dst ^= src;
        }
    }
    Ok(SyncStatus {
        indexed_facts: facts.len(),
        root_count: facts.len() as u64,
        root_fingerprint: fingerprint,
        pending_purges: 0,
    })
}

pub fn shareable_facts_for_connection(
    store: &Store,
    connection_id: FactId,
) -> Result<Vec<Fact>, String> {
    let Some(connection) = connection_response_row(store, connection_id)? else {
        return Ok(Vec::new());
    };
    let Some(local_endpoint) = identity::endpoint::local_endpoint::local_endpoint(store)? else {
        return Ok(Vec::new());
    };
    let Some(remote_endpoint) =
        remote_endpoint_for_connection(&connection, local_endpoint.endpoint)
    else {
        return Ok(Vec::new());
    };
    let endpoint_memberships = endpoint_memberships(store)?;
    let connection_workspaces = connection_workspaces(store, &connection)?;

    let mut facts = Vec::new();
    for row in shareable_fact_rows(store)? {
        let remote_is_member = endpoint_memberships.contains(&(row.workspace_id, remote_endpoint));
        let connection_authorizes_workspace = connection_workspaces.contains(&row.workspace_id);
        if !remote_is_member && !connection_authorizes_workspace {
            continue;
        }
        let Some(fact) = fact_for_shareable_row(store, &row)? else {
            continue;
        };
        facts.push(fact);
    }
    facts.sort_by_key(|fact| (fact.timestamp, fact.id));
    Ok(facts)
}

pub fn shareable_fact_for_connection(
    store: &Store,
    connection_id: FactId,
    fact_id: FactId,
) -> Result<Option<Fact>, String> {
    Ok(shareable_facts_for_connection(store, connection_id)?
        .into_iter()
        .find(|fact| fact.id == fact_id))
}

pub fn connection_ids_for_shareable_fact(
    store: &Store,
    fact_id: FactId,
) -> Result<Vec<FactId>, String> {
    let mut connection_ids = Vec::new();
    for connection in connection_response_rows(store)? {
        if shareable_fact_for_connection(store, connection.connection_id, fact_id)?.is_some() {
            connection_ids.push(connection.connection_id);
        }
    }
    connection_ids.sort();
    connection_ids.dedup();
    Ok(connection_ids)
}

fn connection_response_rows(
    store: &Store,
) -> Result<Vec<connection::response::rows::ConnectionResponseRow>, String> {
    store
        .table_rows(connection::response::rows::CONNECTION_RESPONSE_ROWS)
        .map_err(|err| format!("load connection rows for shareable sync: {err}"))?
        .into_iter()
        .map(|(key, value)| {
            connection::response::rows::decode_connection_response_row(&key, &value)
        })
        .collect()
}

fn connection_response_row(
    store: &Store,
    connection_id: FactId,
) -> Result<Option<connection::response::rows::ConnectionResponseRow>, String> {
    store
        .table_row(
            connection::response::rows::CONNECTION_RESPONSE_ROWS,
            &connection_id,
        )
        .map_err(|err| format!("load connection row for shareable sync: {err}"))?
        .map(|value| {
            connection::response::rows::decode_connection_response_row(&connection_id, &value)
        })
        .transpose()
}

fn endpoint_memberships(store: &Store) -> Result<BTreeSet<(FactId, FactId)>, String> {
    store
        .table_rows(identity::endpoint_shared::rows::ENDPOINT_SHARED_ROWS)
        .map_err(|err| format!("load endpoint memberships for shareable sync: {err}"))?
        .into_iter()
        .map(|(key, value)| {
            identity::endpoint_shared::rows::decode_endpoint_shared_row(&key, &value)
                .map(|row| (row.workspace_id, row.endpoint_id))
        })
        .collect()
}

fn connection_workspaces(
    store: &Store,
    connection: &connection::response::rows::ConnectionResponseRow,
) -> Result<BTreeSet<FactId>, String> {
    let mut workspace_ids = BTreeSet::new();
    let Some(invite_secret_id) = connection_invite_secret_id(store, connection)? else {
        return Ok(workspace_ids);
    };
    if let Some(invite_secret) = wake_loop::persisted_fact(store, &invite_secret_id)? {
        let invite = identity::invite::layout::decode_fact(&invite_secret.bytes)
            .map_err(|_| "connection invite context is not an invite secret".to_string())?;
        if let Some(workspace_id) = invite.workspace_id {
            workspace_ids.insert(workspace_id);
        }
    }
    Ok(workspace_ids)
}

fn connection_invite_secret_id(
    store: &Store,
    connection: &connection::response::rows::ConnectionResponseRow,
) -> Result<Option<FactId>, String> {
    if let Some(response_fact) = wake_loop::persisted_fact(store, &connection.connection_id)? {
        let response = connection::response::layout::decode_fact(&response_fact.bytes)
            .map_err(|_| "connection response fact row is not a connection response".to_string())?;
        return Ok(Some(response.invite_secret_fact_id));
    }
    store
        .table_row(
            connection::request::rows::CONNECTION_REQUEST_ROWS,
            &connection.request_id,
        )
        .map_err(|err| format!("load connection request row for shareable sync: {err}"))?
        .map(|value| {
            connection::request::rows::decode_connection_request_row(&connection.request_id, &value)
                .map(|row| row.invite_secret_fact_id)
        })
        .transpose()
}

pub fn shareable_fact_rows(store: &Store) -> Result<Vec<ShareableFactRow>, String> {
    store
        .table_rows(SHAREABLE_FACT_ROWS)
        .map_err(|err| format!("load shareable fact rows: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_shareable_fact_row(&key, &value))
        .collect()
}

fn fact_for_shareable_row(store: &Store, row: &ShareableFactRow) -> Result<Option<Fact>, String> {
    let Some(fact) = wake_loop::persisted_fact(store, &row.fact_id)? else {
        return Ok(None);
    };
    if fact.timestamp != row.timestamp_ms {
        return Err("shareable fact timestamp does not match fact row".to_string());
    }
    match &fact.scope {
        FactScope::Global => Ok(Some(fact)),
        FactScope::Scoped { kind, id }
            if kind.as_str() == "workspace" && id == &row.workspace_id =>
        {
            Ok(Some(fact))
        }
        _ => Err("shareable fact row does not match a global or workspace-scoped fact".to_string()),
    }
}

fn remote_endpoint_for_connection(
    row: &connection::response::rows::ConnectionResponseRow,
    local_endpoint: FactId,
) -> Option<FactId> {
    if row.from_endpoint == local_endpoint {
        Some(row.to_endpoint)
    } else if row.to_endpoint == local_endpoint {
        Some(row.from_endpoint)
    } else {
        None
    }
}

fn sync_fingerprint(fact: &Fact) -> [u8; 32] {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:sync-range-summary:v1:");
    hash.update(&fact.timestamp.to_be_bytes());
    hash.update(&fact.id);
    *hash.finalize().as_bytes()
}
