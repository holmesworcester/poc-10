//! Connection-maintenance queries over connection-owned read models.
//!
//! The set of peers the local endpoint should keep bootstrapping is not stored
//! as a separate index; it is a query over projected connection rows. A pending
//! bootstrap is a local outbound request row (its `bootstrap_addr` is `Some`)
//! that has no matching connection response yet. The live `maintain_connections`
//! loop reads this; it owns no state of its own.
//!
//! These queries read only connection-owned tables — the request read model and
//! the response read model (active connections) — never auth-owned or
//! endpoint-owned tables. Both are direct fact projections, so replay rebuilds
//! them deterministically and the query result follows.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use crate::core::facts::FactId;
use crate::core::store::Store;

use crate::protocol::connection::response::rows::{
    decode_connection_response_row, CONNECTION_RESPONSE_ROWS,
};

use super::rows::{decode_connection_request_row, CONNECTION_REQUEST_ROWS};

/// A local outbound bootstrap that has not yet been answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingBootstrap {
    /// Local request fact id.
    pub request_id: FactId,
    /// Initiator ephemeral secret used to seal the bootstrap request.
    pub initiator_ephemeral_secret_id: FactId,
    /// Bootstrap return address for the peer.
    pub addr: SocketAddr,
}

/// Connection-maintenance status: pending bootstraps and active connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MaintenanceStatus {
    /// Local outbound requests still awaiting a response, ordered by request id.
    pub pending: Vec<PendingBootstrap>,
    /// Established connections (materialized connection responses).
    pub active_connections: usize,
}

/// Request ids that already have a materialized connection response.
fn answered_request_ids(store: &Store) -> Result<BTreeSet<FactId>, String> {
    store
        .table_rows(CONNECTION_RESPONSE_ROWS)
        .map_err(|err| format!("read connection responses: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_connection_response_row(&key, &value).map(|row| row.request_id))
        .collect()
}

/// Local outbound requests that have a route and no response yet.
///
/// This is the pending bootstrap candidate set: request rows whose
/// `bootstrap_addr` is `Some` (local outbound with a route) minus those answered
/// by a connection response.
pub fn pending_bootstrap_requests(store: &Store) -> Result<Vec<PendingBootstrap>, String> {
    let answered = answered_request_ids(store)?;
    let mut pending = Vec::new();
    for (key, value) in store
        .table_rows(CONNECTION_REQUEST_ROWS)
        .map_err(|err| format!("read connection requests: {err}"))?
    {
        let row = decode_connection_request_row(&key, &value)?;
        let Some(addr) = row.bootstrap_addr else {
            continue;
        };
        if answered.contains(&row.request_id) {
            continue;
        }
        pending.push(PendingBootstrap {
            request_id: row.request_id,
            initiator_ephemeral_secret_id: row.initiator_ephemeral_secret_fact_id,
            addr,
        });
    }
    pending.sort_by(|left, right| left.request_id.cmp(&right.request_id));
    Ok(pending)
}

/// Read connection-maintenance status from connection-owned read models.
pub fn connection_maintenance_status(store: &Store) -> Result<MaintenanceStatus, String> {
    let pending = pending_bootstrap_requests(store)?;
    let active_connections = store
        .table_row_count(CONNECTION_RESPONSE_ROWS)
        .map_err(|err| format!("count active connections: {err}"))?;
    Ok(MaintenanceStatus {
        pending,
        active_connections,
    })
}
