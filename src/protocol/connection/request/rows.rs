//! Durable rows for admitted connection requests.
//!
//! Rows are keyed by request fact id and store the endpoint pair, the invite,
//! invite-secret, and initiator ephemeral-secret dependency ids, and — for a
//! local outbound request with a reachable route — the bootstrap return address.
//! That compact row lets response projection and the connection-maintenance
//! query resolve a request without re-decoding the full fact body.
//!
//! `bootstrap_addr` is a direct projection of the request fact: it is `Some`
//! only when the request is the local outbound side and carries a `to_listen_addr`
//! route. The live maintenance loop treats a request row whose `bootstrap_addr`
//! is `Some` and which has no matching connection response as a pending bootstrap
//! candidate. There is no separate candidate index; the candidate set is a query
//! over these projected rows.
//!
//! Change this file for request row compatibility. Projection owns when the row
//! is written, layout owns canonical request fact bytes, and `queries.rs` owns
//! the pending-bootstrap selection.

use std::net::SocketAddr;

use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};

use super::create as addr;
use super::fact::{ConnectionRequestFact, EndpointId};

pub const CONNECTION_REQUEST_ROWS: TableName = TableName::new("connection_request_rows");
pub const ROW_VALUE_BYTES: usize = 32 + 32 + 32 + 32 + 32 + addr::ADDR_BLOCK_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionRequestRow {
    pub request_id: FactId,
    pub from_endpoint: EndpointId,
    pub to_endpoint: EndpointId,
    pub invite_fact_id: FactId,
    pub invite_secret_fact_id: FactId,
    pub initiator_ephemeral_secret_fact_id: FactId,
    /// Bootstrap return address for a local outbound request; `None` for received
    /// requests or local requests without a route.
    pub bootstrap_addr: Option<SocketAddr>,
}

pub fn connection_request_key(request_id: &FactId) -> Vec<u8> {
    request_id.to_vec()
}

pub fn connection_request_row(
    request_id: FactId,
    fact: &ConnectionRequestFact,
    bootstrap_addr: Option<SocketAddr>,
) -> Result<TableRow, String> {
    let mut value = vec![0; ROW_VALUE_BYTES];
    value[0..32].copy_from_slice(&fact.from_endpoint);
    value[32..64].copy_from_slice(&fact.to_endpoint);
    value[64..96].copy_from_slice(&fact.invite_fact_id);
    value[96..128].copy_from_slice(&fact.invite_secret_fact_id);
    value[128..160].copy_from_slice(&fact.initiator_ephemeral_secret_fact_id);
    value[160..].copy_from_slice(&addr::encode_optional_addr(bootstrap_addr)?);
    Ok(TableRow {
        table: CONNECTION_REQUEST_ROWS,
        key: connection_request_key(&request_id),
        value,
    })
}

pub fn decode_connection_request_row(
    key: &[u8],
    value: &[u8],
) -> Result<ConnectionRequestRow, String> {
    if key.len() != 32 {
        return Err("connection request row key must be the request fact id".to_string());
    }
    if value.len() != ROW_VALUE_BYTES {
        return Err("connection request row value is malformed".to_string());
    }
    let mut request_id = [0; 32];
    request_id.copy_from_slice(key);
    let mut from_endpoint = [0; 32];
    from_endpoint.copy_from_slice(&value[0..32]);
    let mut to_endpoint = [0; 32];
    to_endpoint.copy_from_slice(&value[32..64]);
    let mut invite_fact_id = [0; 32];
    invite_fact_id.copy_from_slice(&value[64..96]);
    let mut invite_secret_fact_id = [0; 32];
    invite_secret_fact_id.copy_from_slice(&value[96..128]);
    let mut initiator_ephemeral_secret_fact_id = [0; 32];
    initiator_ephemeral_secret_fact_id.copy_from_slice(&value[128..160]);
    let mut addr_bytes = [0u8; addr::ADDR_BLOCK_BYTES];
    addr_bytes.copy_from_slice(&value[160..]);
    let bootstrap_addr = addr::decode_optional_addr(&addr_bytes)?;
    Ok(ConnectionRequestRow {
        request_id,
        from_endpoint,
        to_endpoint,
        invite_fact_id,
        invite_secret_fact_id,
        initiator_ephemeral_secret_fact_id,
        bootstrap_addr,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_row_roundtrips_with_and_without_bootstrap_addr() {
        let fact = ConnectionRequestFact {
            from_endpoint: [1; 32],
            to_endpoint: [2; 32],
            nonce: [3; 32],
            invite_fact_id: [4; 32],
            bootstrap_hash: [5; 32],
            invite_signature: [6; 64],
            invite_secret_fact_id: [7; 32],
            initiator_ephemeral_secret_fact_id: [8; 32],
            initiator_ephemeral_public_key: [9; 32],
            from_listen_addr: None,
            to_listen_addr: Some("127.0.0.1:41001".parse().unwrap()),
        };
        for bootstrap_addr in [Some("127.0.0.1:41001".parse().unwrap()), None] {
            let row = connection_request_row([10; 32], &fact, bootstrap_addr).expect("encode");
            let decoded = decode_connection_request_row(&row.key, &row.value).expect("decode");
            assert_eq!(decoded.request_id, [10; 32]);
            assert_eq!(decoded.to_endpoint, fact.to_endpoint);
            assert_eq!(
                decoded.initiator_ephemeral_secret_fact_id,
                fact.initiator_ephemeral_secret_fact_id
            );
            assert_eq!(decoded.bootstrap_addr, bootstrap_addr);
        }
    }
}
