//! Durable rows for materialized connection responses.
//!
//! The response fact id is the connection id, so rows are keyed by that id. The
//! value stores endpoint ids, answered request id, responder ephemeral public
//! key, handshake hash, and the local connection secret used for frame opening
//! and sealing.
//!
//! These rows are local connection capability state. Change this file for row
//! key/value compatibility; projection owns when rows are written and when
//! connection context is offered.

use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};

use super::fact::{BootstrapResponseFact, EndpointId};

pub const BOOTSTRAP_RESPONSE_ROWS: TableName = TableName::new("bootstrap_response_rows");
pub const ROW_VALUE_BYTES: usize = 32 + 32 + 32 + 32 + 32 + 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapResponseRow {
    pub connection_id: FactId,
    pub from_endpoint: EndpointId,
    pub to_endpoint: EndpointId,
    pub request_id: FactId,
    pub responder_ephemeral_public_key: EndpointId,
    pub handshake_hash: [u8; 32],
    pub connection_secret: [u8; 32],
}

pub fn bootstrap_response_key(connection_id: &FactId) -> Vec<u8> {
    connection_id.to_vec()
}

pub fn bootstrap_response_row(
    connection_id: FactId,
    fact: &BootstrapResponseFact,
) -> Result<TableRow, String> {
    let mut value = vec![0; ROW_VALUE_BYTES];
    value[0..32].copy_from_slice(&fact.from_endpoint);
    value[32..64].copy_from_slice(&fact.to_endpoint);
    value[64..96].copy_from_slice(&fact.request_id);
    value[96..128].copy_from_slice(&fact.responder_ephemeral_public_key);
    value[128..160].copy_from_slice(&fact.handshake_hash);
    value[160..192].copy_from_slice(&fact.connection_secret);
    Ok(TableRow {
        table: BOOTSTRAP_RESPONSE_ROWS,
        key: bootstrap_response_key(&connection_id),
        value,
    })
}

pub fn decode_bootstrap_response_row(
    key: &[u8],
    value: &[u8],
) -> Result<BootstrapResponseRow, String> {
    if key.len() != 32 {
        return Err("connection response row key must be the connection id".to_string());
    }
    if value.len() != ROW_VALUE_BYTES {
        return Err("connection response row value is malformed".to_string());
    }
    let mut connection_id = [0; 32];
    connection_id.copy_from_slice(key);
    let mut from_endpoint = [0; 32];
    from_endpoint.copy_from_slice(&value[0..32]);
    let mut to_endpoint = [0; 32];
    to_endpoint.copy_from_slice(&value[32..64]);
    let mut request_id = [0; 32];
    request_id.copy_from_slice(&value[64..96]);
    let mut responder_ephemeral_public_key = [0; 32];
    responder_ephemeral_public_key.copy_from_slice(&value[96..128]);
    let mut handshake_hash = [0; 32];
    handshake_hash.copy_from_slice(&value[128..160]);
    let mut connection_secret = [0; 32];
    connection_secret.copy_from_slice(&value[160..192]);
    Ok(BootstrapResponseRow {
        connection_id,
        from_endpoint,
        to_endpoint,
        request_id,
        responder_ephemeral_public_key,
        handshake_hash,
        connection_secret,
    })
}
