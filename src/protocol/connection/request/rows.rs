//! Durable rows for admitted connection requests.
//!
//! Rows are keyed by request fact id and store the endpoint pair plus the
//! invite, invite-secret, and initiator ephemeral-secret dependency ids. That
//! compact row lets response projection and diagnostics resolve request
//! dependencies without re-decoding the full fact body.
//!
//! Change this file for request row compatibility. Projection owns when the row
//! is written, and layout owns canonical request fact bytes.

use std::net::SocketAddr;

use crate::core::facts::FactId;
use crate::core::store::{Store, TableName, TableRow};

use super::create as request_addr;
use super::fact::{ConnectionRequestFact, EndpointId};

pub const CONNECTION_REQUEST_ROWS: TableName = TableName::new("connection_request_rows");
pub const ROW_VALUE_BYTES: usize = 32 + 32 + 32 + 32 + 32;
pub const CONNECTION_MAINTENANCE_CANDIDATE_ROWS: TableName =
    TableName::new("connection_maintenance_candidate_rows");

const CANDIDATE_ROW_VALUE_BYTES: usize = 32 + 32 + 32 + request_addr::ADDR_BLOCK_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionRequestRow {
    pub request_id: FactId,
    pub from_endpoint: EndpointId,
    pub to_endpoint: EndpointId,
    pub invite_fact_id: FactId,
    pub invite_secret_fact_id: FactId,
    pub initiator_ephemeral_secret_fact_id: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionMaintenanceCandidate {
    pub request_id: FactId,
    pub from_endpoint: EndpointId,
    pub to_endpoint: EndpointId,
    pub initiator_ephemeral_secret_id: FactId,
    pub addr: SocketAddr,
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

pub fn connection_maintenance_candidate_key(request_id: &FactId) -> Vec<u8> {
    request_id.to_vec()
}

pub fn connection_maintenance_candidate_row(
    candidate: ConnectionMaintenanceCandidate,
) -> Result<TableRow, String> {
    let mut value = Vec::with_capacity(CANDIDATE_ROW_VALUE_BYTES);
    value.extend_from_slice(&candidate.from_endpoint);
    value.extend_from_slice(&candidate.to_endpoint);
    value.extend_from_slice(&candidate.initiator_ephemeral_secret_id);
    value.extend_from_slice(&request_addr::encode_optional_addr(Some(candidate.addr))?);
    Ok(TableRow {
        table: CONNECTION_MAINTENANCE_CANDIDATE_ROWS,
        key: connection_maintenance_candidate_key(&candidate.request_id),
        value,
    })
}

pub fn decode_connection_maintenance_candidate_row(
    key: &[u8],
    value: &[u8],
) -> Result<ConnectionMaintenanceCandidate, String> {
    if key.len() != 32 {
        return Err("connection candidate row key must be the request id".to_string());
    }
    if value.len() != CANDIDATE_ROW_VALUE_BYTES {
        return Err("connection candidate row value is malformed".to_string());
    }
    let request_id = bytes32(key);
    let from_endpoint = bytes32(&value[0..32]);
    let to_endpoint = bytes32(&value[32..64]);
    let initiator_ephemeral_secret_id = bytes32(&value[64..96]);
    let mut addr_bytes = [0; request_addr::ADDR_BLOCK_BYTES];
    addr_bytes.copy_from_slice(&value[96..]);
    let addr = request_addr::decode_optional_addr(&addr_bytes)?
        .ok_or_else(|| "connection candidate row addr is missing".to_string())?;
    Ok(ConnectionMaintenanceCandidate {
        request_id,
        from_endpoint,
        to_endpoint,
        initiator_ephemeral_secret_id,
        addr,
    })
}

pub fn connection_maintenance_candidates(
    store: &Store,
) -> Result<Vec<ConnectionMaintenanceCandidate>, String> {
    let rows = store
        .table_rows(CONNECTION_MAINTENANCE_CANDIDATE_ROWS)
        .map_err(|err| format!("load connection candidates: {err}"))?;
    rows.into_iter()
        .map(|(key, value)| decode_connection_maintenance_candidate_row(&key, &value))
        .collect()
}

pub fn connection_maintenance_candidate_count(store: &Store) -> Result<usize, String> {
    store
        .table_row_count(CONNECTION_MAINTENANCE_CANDIDATE_ROWS)
        .map_err(|err| format!("count connection candidates: {err}"))
}

fn bytes32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("slice length checked by caller")
}
