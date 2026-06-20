//! Connection-mode trigger.
//!
//! `choose_connection_mode` is the pure, locally-checkable decision made at
//! connect time: can we open a membership connection to a target endpoint
//! without an invite? That is true exactly when we hold mutual `endpoint_shared`
//! membership with the target in some workspace.
//!
//! This reads only `endpoint_shared` membership. It is side-effect free and
//! never opens sockets or remembers endpoint addresses.

use std::net::SocketAddr;

use crate::core::db::{Db, DEFAULT_QUERY_LIMIT};
use crate::core::facts::FactId;
use rusqlite::{params, OptionalExtension, Row};

use crate::protocol::auth::endpoint::author::local_endpoint;
use crate::protocol::auth::endpoint_shared::queries::all_memberships;
use crate::protocol::connection::connection::queries::answered_request_ids;
use crate::protocol::connection::request::{
    encode::ADDR_BLOCK_BYTES, project::decode::decode_optional_addr,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRequestRow {
    pub request_id: FactId,
    pub request_sent_id: FactId,
    pub initiator_ephemeral_secret_fact_id: FactId,
    /// Reachable address to (re)send this request to. `None` marks a row that
    /// must not be re-sent.
    pub peer_addr: Option<SocketAddr>,
    pub sealed_request_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapConnectionAttemptRow {
    pub invite_accepted_fact_id: FactId,
    pub request_id: FactId,
}

pub fn decode_connection_request_row(row: &Row<'_>) -> rusqlite::Result<ConnectionRequestRow> {
    let peer_addr_block: Vec<u8> = row.get(3)?;
    let peer_addr_block: [u8; ADDR_BLOCK_BYTES] =
        peer_addr_block.as_slice().try_into().map_err(|_| {
            rusqlite::Error::InvalidParameterName(
                "connection request row peer_addr block is malformed".to_string(),
            )
        })?;
    let peer_addr =
        decode_optional_addr(&peer_addr_block).map_err(rusqlite::Error::InvalidParameterName)?;
    Ok(ConnectionRequestRow {
        request_id: row.get(0)?,
        request_sent_id: row.get(1)?,
        initiator_ephemeral_secret_fact_id: row.get(2)?,
        peer_addr,
        sealed_request_bytes: row.get(4)?,
    })
}

fn decode_bootstrap_connection_attempt_row(
    row: &Row<'_>,
) -> rusqlite::Result<BootstrapConnectionAttemptRow> {
    Ok(BootstrapConnectionAttemptRow {
        invite_accepted_fact_id: row.get(0)?,
        request_id: row.get(1)?,
    })
}

pub fn bootstrap_connection_attempt_rows(
    store: &Db,
) -> Result<Vec<BootstrapConnectionAttemptRow>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT invite_accepted_fact_id, request_id
             FROM bootstrap_connection_attempt_rows
             ORDER BY invite_accepted_fact_id
             LIMIT ?1",
        )
        .map_err(|err| format!("read bootstrap connection attempt rows: {err}"))?;
    let rows = stmt
        .query_map(
            params![DEFAULT_QUERY_LIMIT as i64],
            decode_bootstrap_connection_attempt_row,
        )
        .map_err(|err| format!("read bootstrap connection attempt rows: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("decode bootstrap connection attempt rows: {err}"))
}

/// A membership connection we can open to a known endpoint without an invite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembershipConnectionPlan {
    pub workspace_id: FactId,
    /// Our own `endpoint_shared` fact id in that workspace (the membership
    /// witness the request carries).
    pub initiator_endpoint_shared_id: FactId,
    pub to_endpoint: FactId,
}

/// Decide whether a membership connection to `target_endpoint` is possible.
///
/// Returns `Some` iff we hold our own `endpoint_shared` and the target's
/// `endpoint_shared` in the same workspace (mutual membership). Otherwise
/// `None`: the caller must bootstrap from an invite instead.
pub fn choose_connection_mode(
    store: &Db,
    target_endpoint: FactId,
) -> Result<Option<MembershipConnectionPlan>, String> {
    let Some(local) = local_endpoint(store)? else {
        return Ok(None);
    };
    if target_endpoint == local.endpoint {
        return Ok(None);
    }

    let memberships = all_memberships(store)?;

    // Find a workspace where both the target and our own endpoint are admitted.
    for row in memberships
        .iter()
        .filter(|row| row.endpoint_id == target_endpoint)
    {
        let Some(local_membership) = memberships.iter().find(|other| {
            other.workspace_id == row.workspace_id && other.endpoint_id == local.endpoint
        }) else {
            continue;
        };
        return Ok(Some(MembershipConnectionPlan {
            workspace_id: row.workspace_id,
            initiator_endpoint_shared_id: local_membership.endpoint_shared_id,
            to_endpoint: target_endpoint,
        }));
    }
    Ok(None)
}

/// One local outbound connection request still awaiting a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingConnectionRequest {
    pub request_id: FactId,
    pub initiator_ephemeral_secret_id: FactId,
    pub addr: SocketAddr,
    pub sealed_request_bytes: Vec<u8>,
}

/// Local outbound membership request rows whose request id has no connection
/// (response) row yet. The live `maintain_connections` loop queues one send per
/// entry; an answered request drops out so a connected peer stops being retried.
pub fn pending_connection_requests(store: &Db) -> Result<Vec<PendingConnectionRequest>, String> {
    let answered = answered_request_ids(store)?;
    let mut pending = Vec::new();
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT request_id,
                    request_sent_id,
                    initiator_ephemeral_secret_fact_id,
                    peer_addr,
                    sealed_request_bytes
             FROM connection_request_rows
             ORDER BY request_id
             LIMIT ?1",
        )
        .map_err(|err| format!("read membership connection request rows: {err}"))?;
    let rows = stmt
        .query_map(
            params![DEFAULT_QUERY_LIMIT as i64],
            decode_connection_request_row,
        )
        .map_err(|err| format!("read membership connection request rows: {err}"))?;
    for row in rows {
        let row = row.map_err(|err| format!("decode connection request row: {err}"))?;
        let Some(addr) = row.peer_addr else {
            continue;
        };
        if answered.contains(&row.request_id) {
            continue;
        }
        pending.push(PendingConnectionRequest {
            request_id: row.request_id,
            initiator_ephemeral_secret_id: row.initiator_ephemeral_secret_fact_id,
            addr,
            sealed_request_bytes: row.sealed_request_bytes,
        });
    }
    Ok(pending)
}

pub fn request_by_id(
    store: &Db,
    request_id: &FactId,
) -> Result<Option<ConnectionRequestRow>, String> {
    store
        .conn()
        .query_row(
            "SELECT request_id,
                    request_sent_id,
                    initiator_ephemeral_secret_fact_id,
                    peer_addr,
                    sealed_request_bytes
             FROM connection_request_rows
             WHERE request_id = ?1
             LIMIT 1",
            params![request_id],
            decode_connection_request_row,
        )
        .optional()
        .map_err(|err| format!("read connection request row: {err}"))
}

pub fn request_route_by_id(store: &Db, request_id: &FactId) -> Result<Option<SocketAddr>, String> {
    Ok(request_by_id(store, request_id)?.and_then(|row| row.peer_addr))
}

// Tests.
// One guard: no local endpoint yields no membership connection.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::db::Db;
    use crate::core::schema::CORE_SCHEMA_SOURCE;
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;

    // The full transition — Bootstrap before mutual membership, Normal after a
    // bootstrap sync, and content reconnect without an invite — is covered by the
    // `cli_membership_connect_reconnects_known_peer_without_invite` black-box test.
    // Here we only pin the local guard: with no local endpoint identity there is
    // no membership connection to choose.
    #[test]
    fn no_local_endpoint_yields_no_membership_connection() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
            .expect("store");
        assert_eq!(
            choose_connection_mode(&store, [9; 32]).expect("query"),
            None
        );
    }
}
