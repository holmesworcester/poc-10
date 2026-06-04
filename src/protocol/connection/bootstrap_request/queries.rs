//! Read-only queries over admitted bootstrap requests.
//!
//! `pending_bootstrap_requests` is the live connection-maintenance selection:
//! local outbound request rows (a peer address is present) whose request id has
//! no connection (response) row yet. The maintenance loop queues one send per
//! entry, and an answered request drops out so a connected peer stops being
//! retried. This is a pure read over connection-owned rows, not a candidate
//! index the projector has to keep in sync.

use std::net::SocketAddr;

use crate::core::facts::FactId;
use crate::core::store::Store;

use crate::protocol::connection::bootstrap_response::rows::answered_request_ids;

use super::rows::{decode_bootstrap_request_row, BOOTSTRAP_REQUEST_ROWS};

/// One local outbound bootstrap request still awaiting a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingBootstrapRequest {
    pub request_sent_id: FactId,
    pub request_id: FactId,
    pub initiator_ephemeral_secret_id: FactId,
    pub addr: SocketAddr,
    pub sealed_request_bytes: Vec<u8>,
}

pub fn pending_bootstrap_requests(store: &Store) -> Result<Vec<PendingBootstrapRequest>, String> {
    let answered = answered_request_ids(store)?;
    let mut pending = Vec::new();
    for (key, value) in store
        .table_rows(BOOTSTRAP_REQUEST_ROWS)
        .map_err(|err| format!("read bootstrap request rows: {err}"))?
    {
        let row = decode_bootstrap_request_row(&key, &value)?;
        let Some(addr) = row.peer_addr else {
            continue;
        };
        if answered.contains(&row.request_id) {
            continue;
        }
        pending.push(PendingBootstrapRequest {
            request_sent_id: row.request_sent_id,
            request_id: row.request_id,
            initiator_ephemeral_secret_id: row.initiator_ephemeral_secret_fact_id,
            addr,
            sealed_request_bytes: row.sealed_request_bytes,
        });
    }
    Ok(pending)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::schema::CORE_SCHEMA_SOURCE;
    use crate::core::store::Store;
    use crate::protocol::connection::bootstrap_request::fact::BootstrapRequestFact;
    use crate::protocol::connection::bootstrap_request::rows::bootstrap_request_row;
    use crate::protocol::connection::bootstrap_response::rows::{
        connection_row, ConnectionRowFields,
    };
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;

    fn request_fact(
        ephemeral_id: FactId,
        to_listen_addr: Option<SocketAddr>,
    ) -> BootstrapRequestFact {
        BootstrapRequestFact {
            from_endpoint: [1; 32],
            to_endpoint: [2; 32],
            nonce: [3; 32],
            invite_fact_id: [4; 32],
            bootstrap_hash: [5; 32],
            invite_signature: [0; 64],
            invite_secret_fact_id: [6; 32],
            initiator_ephemeral_secret_fact_id: ephemeral_id,
            initiator_ephemeral_public_key: [7; 32],
            from_listen_addr: None,
            to_listen_addr,
        }
    }

    #[test]
    fn pending_bootstrap_requests_excludes_received_no_route_and_answered() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("store");
        let addr: SocketAddr = "127.0.0.1:41001".parse().expect("addr");

        // A: local outbound with a route, unanswered -> pending.
        // C: local outbound with a route, but answered -> not pending.
        // B: a received request (no peer address) -> never re-sent.
        let sealed = vec![0; super::super::transit::SEALED_CONNECTION_REQUEST_BYTES];
        let row_a = bootstrap_request_row(
            [0xA1; 32],
            [0xA2; 32],
            &request_fact([0xAE; 32], Some(addr)),
            Some(addr),
            &sealed,
        )
        .expect("row a");
        let row_c = bootstrap_request_row(
            [0xC3; 32],
            [0xC4; 32],
            &request_fact([0xCE; 32], Some(addr)),
            Some(addr),
            &sealed,
        )
        .expect("row c");
        let row_b = bootstrap_request_row(
            [0xB2; 32],
            [0xB3; 32],
            &request_fact([0xBE; 32], Some(addr)),
            None,
            &sealed,
        )
        .expect("row b");
        let answered_c = connection_row(ConnectionRowFields {
            connection_id: [0xCC; 32],
            from_endpoint: [2; 32],
            to_endpoint: [1; 32],
            request_id: [0xC3; 32],
            responder_ephemeral_public_key: [8; 32],
            handshake_hash: [9; 32],
            connection_secret: [10; 32],
        })
        .expect("answered c");
        store
            .insert_table_rows(vec![row_a, row_c, row_b, answered_c])
            .expect("seed rows");

        let pending = pending_bootstrap_requests(&store).expect("pending");
        assert_eq!(
            pending.len(),
            1,
            "only the unanswered local outbound request"
        );
        assert_eq!(pending[0].request_id, [0xA1; 32]);
        assert_eq!(pending[0].request_sent_id, [0xA2; 32]);
        assert_eq!(pending[0].initiator_ephemeral_secret_id, [0xAE; 32]);
        assert_eq!(pending[0].addr, addr);
    }
}
