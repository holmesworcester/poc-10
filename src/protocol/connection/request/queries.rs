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

use crate::core::facts::FactId;
use crate::core::store::Store;

use crate::protocol::auth::endpoint::create::local_endpoint;
use crate::protocol::auth::endpoint_shared::queries::all_memberships;
use crate::protocol::connection::connection::rows::answered_request_ids;

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
    store: &Store,
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
pub fn pending_connection_requests(store: &Store) -> Result<Vec<PendingConnectionRequest>, String> {
    let answered = answered_request_ids(store)?;
    let mut pending = Vec::new();
    for (key, value) in store
        .table_rows(super::rows::CONNECTION_REQUEST_ROWS)
        .map_err(|err| format!("read membership connection request rows: {err}"))?
    {
        let row = super::rows::decode_connection_request_row(&key, &value)?;
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

pub fn pending_membership_requests(store: &Store) -> Result<Vec<PendingConnectionRequest>, String> {
    pending_connection_requests(store)
}

pub fn request_by_id(
    store: &Store,
    request_id: &FactId,
) -> Result<Option<super::rows::ConnectionRequestRow>, String> {
    let row = store
        .table_row(
            super::rows::CONNECTION_REQUEST_ROWS,
            &super::rows::connection_request_key(request_id),
        )
        .map_err(|err| format!("read connection request row: {err}"))?;
    row.map(|value| super::rows::decode_connection_request_row(request_id, &value))
        .transpose()
}

pub fn request_route_by_id(
    store: &Store,
    request_id: &FactId,
) -> Result<Option<SocketAddr>, String> {
    Ok(request_by_id(store, request_id)?.and_then(|row| row.peer_addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::schema::CORE_SCHEMA_SOURCE;
    use crate::core::store::Store;
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;

    // The full transition — Bootstrap before mutual membership, Normal after a
    // bootstrap sync, and content reconnect without an invite — is covered by the
    // `cli_membership_connect_reconnects_known_peer_without_invite` black-box test.
    // Here we only pin the local guard: with no local endpoint identity there is
    // no membership connection to choose.
    #[test]
    fn no_local_endpoint_yields_no_membership_connection() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("store");
        assert_eq!(
            choose_connection_mode(&store, [9; 32]).expect("query"),
            None
        );
    }
}
