//! Connection-request projection rows.
//!
//! Rows are keyed by the request fact id. The value records the endpoint pair
//! and the dependency edges (invite fact, invite secret, initiator ephemeral
//! secret) so downstream consumers can resolve the request without re-decoding
//! the full fact body.

use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};

use super::fact::{ConnectionRequestFact, EndpointId};

pub const CONNECTION_REQUEST_ROWS: TableName = TableName::new("connection_request_rows");
pub const ROW_VALUE_BYTES: usize = 32 + 32 + 32 + 32 + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionRequestRow {
    pub request_id: FactId,
    pub from_endpoint: EndpointId,
    pub to_endpoint: EndpointId,
    pub invite_fact_id: FactId,
    pub invite_secret_fact_id: FactId,
    pub initiator_ephemeral_secret_fact_id: FactId,
}

pub fn connection_request_key(request_id: &FactId) -> Vec<u8> {
    request_id.to_vec()
}

pub fn connection_request_row(
    request_id: FactId,
    fact: &ConnectionRequestFact,
) -> Result<TableRow, String> {
    let mut value = vec![0; ROW_VALUE_BYTES];
    value[0..32].copy_from_slice(&fact.from_endpoint);
    value[32..64].copy_from_slice(&fact.to_endpoint);
    value[64..96].copy_from_slice(&fact.invite_fact_id);
    value[96..128].copy_from_slice(&fact.invite_secret_fact_id);
    value[128..160].copy_from_slice(&fact.initiator_ephemeral_secret_fact_id);
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
    Ok(ConnectionRequestRow {
        request_id,
        from_endpoint,
        to_endpoint,
        invite_fact_id,
        invite_secret_fact_id,
        initiator_ephemeral_secret_fact_id,
    })
}
