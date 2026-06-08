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

use crate::protocol::auth::endpoint::author::local_endpoint;
use crate::protocol::auth::endpoint_shared::queries::all_memberships;
use crate::protocol::connection::connection::queries::answered_request_ids;
use crate::protocol::connection::request::{
    decode::decode_optional_addr, encode::ADDR_BLOCK_BYTES,
};

use super::{
    BOOTSTRAP_CONNECTION_ATTEMPT_ROWS, BOOTSTRAP_CONNECTION_ATTEMPT_ROW_SCHEMA,
    CONNECTION_REQUEST_ROWS, CONNECTION_REQUEST_ROW_SCHEMA,
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

pub fn decode_connection_request_row(
    key: &[u8],
    value: &[u8],
) -> Result<ConnectionRequestRow, String> {
    let key_fields = CONNECTION_REQUEST_ROW_SCHEMA.decode_key(key)?;
    let value_fields = CONNECTION_REQUEST_ROW_SCHEMA.decode_value(value)?;
    let peer_addr_block: [u8; ADDR_BLOCK_BYTES] = value_fields[2]
        .as_bytes("peer_addr")?
        .try_into()
        .map_err(|_| "connection request row peer_addr block is malformed".to_string())?;
    let peer_addr = decode_optional_addr(&peer_addr_block)?;
    Ok(ConnectionRequestRow {
        request_id: key_fields[0].as_bytes32("request_id")?,
        request_sent_id: value_fields[0].as_bytes32("request_sent_id")?,
        initiator_ephemeral_secret_fact_id: value_fields[1]
            .as_bytes32("initiator_ephemeral_secret_fact_id")?,
        peer_addr,
        sealed_request_bytes: value_fields[3].as_bytes("sealed_request_bytes")?.to_vec(),
    })
}

fn decode_bootstrap_connection_attempt_row(
    key: &[u8],
    value: &[u8],
) -> Result<BootstrapConnectionAttemptRow, String> {
    let key_fields = BOOTSTRAP_CONNECTION_ATTEMPT_ROW_SCHEMA.decode_key(key)?;
    let value_fields = BOOTSTRAP_CONNECTION_ATTEMPT_ROW_SCHEMA.decode_value(value)?;
    Ok(BootstrapConnectionAttemptRow {
        invite_accepted_fact_id: key_fields[0].as_bytes32("invite_accepted_fact_id")?,
        request_id: value_fields[0].as_bytes32("request_id")?,
    })
}

pub fn bootstrap_connection_attempt_rows(
    store: &Store,
) -> Result<Vec<BootstrapConnectionAttemptRow>, String> {
    store
        .table_rows(BOOTSTRAP_CONNECTION_ATTEMPT_ROWS)
        .map_err(|err| format!("read bootstrap connection attempt rows: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_bootstrap_connection_attempt_row(&key, &value))
        .collect()
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
        .table_rows(CONNECTION_REQUEST_ROWS)
        .map_err(|err| format!("read membership connection request rows: {err}"))?
    {
        let row = decode_connection_request_row(&key, &value)?;
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
    store: &Store,
    request_id: &FactId,
) -> Result<Option<ConnectionRequestRow>, String> {
    let row = store
        .table_row(
            CONNECTION_REQUEST_ROWS,
            &super::connection_request_key(request_id),
        )
        .map_err(|err| format!("read connection request row: {err}"))?;
    row.map(|value| decode_connection_request_row(request_id, &value))
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

    #[test]
    fn connection_request_row_roundtrips_through_schema() {
        use crate::protocol::connection::request::encode::SEALED_FACT_BYTES;

        let sealed = vec![7u8; SEALED_FACT_BYTES];
        let row = super::super::connection_request_row(
            [1; 32],
            [2; 32],
            [3; 32],
            Some("127.0.0.1:41000".parse().unwrap()),
            &sealed,
        )
        .expect("connection request row");
        let decoded =
            decode_connection_request_row(&row.key, &row.value).expect("decode request row");
        assert_eq!(decoded.request_id, [1; 32]);
        assert_eq!(decoded.request_sent_id, [2; 32]);
        assert_eq!(decoded.initiator_ephemeral_secret_fact_id, [3; 32]);
        assert_eq!(decoded.peer_addr, Some("127.0.0.1:41000".parse().unwrap()));
        assert_eq!(decoded.sealed_request_bytes, sealed);
    }

    #[test]
    fn bootstrap_attempt_row_roundtrips_through_schema() {
        let row =
            super::super::bootstrap_connection_attempt_row([1; 32], [2; 32]).expect("attempt row");
        let decoded = decode_bootstrap_connection_attempt_row(&row.key, &row.value)
            .expect("decode attempt row");
        assert_eq!(decoded.invite_accepted_fact_id, [1; 32]);
        assert_eq!(decoded.request_id, [2; 32]);
    }
}
