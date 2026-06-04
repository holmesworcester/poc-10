//! Durable rows for materialized connections.
//!
//! The connection fact id is the connection id, so rows are keyed by
//! that id. The row stores the endpoint pair, answered request id, responder
//! ephemeral public key, handshake hash, connection secret, and the
//! connection-scoped addresses used for frame sends.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use crate::core::facts::FactId;
use crate::core::store::{Store, TableName, TableRow};

use crate::protocol::connection::request::create::{
    decode_optional_addr, encode_optional_addr, ADDR_BLOCK_BYTES,
};

pub const CONNECTION_ROWS: TableName = TableName::new("connection_rows");
pub const ROW_VALUE_BYTES: usize =
    32 + 32 + 32 + 32 + 32 + 32 + ADDR_BLOCK_BYTES + ADDR_BLOCK_BYTES;
pub type EndpointId = FactId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionRow {
    pub connection_id: FactId,
    pub from_endpoint: EndpointId,
    pub to_endpoint: EndpointId,
    pub request_id: FactId,
    pub responder_ephemeral_public_key: EndpointId,
    pub handshake_hash: [u8; 32],
    pub connection_secret: [u8; 32],
    pub responder_addr: Option<SocketAddr>,
    pub initiator_addr: Option<SocketAddr>,
}

pub fn connection_key(connection_id: &FactId) -> Vec<u8> {
    connection_id.to_vec()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionRowFields {
    pub connection_id: FactId,
    pub from_endpoint: EndpointId,
    pub to_endpoint: EndpointId,
    pub request_id: FactId,
    pub responder_ephemeral_public_key: EndpointId,
    pub handshake_hash: [u8; 32],
    pub connection_secret: [u8; 32],
    pub responder_addr: Option<SocketAddr>,
    pub initiator_addr: Option<SocketAddr>,
}

impl ConnectionRowFields {
    pub fn without_addresses(
        connection_id: FactId,
        from_endpoint: EndpointId,
        to_endpoint: EndpointId,
        request_id: FactId,
        responder_ephemeral_public_key: EndpointId,
        handshake_hash: [u8; 32],
        connection_secret: [u8; 32],
    ) -> Self {
        Self {
            connection_id,
            from_endpoint,
            to_endpoint,
            request_id,
            responder_ephemeral_public_key,
            handshake_hash,
            connection_secret,
            responder_addr: None,
            initiator_addr: None,
        }
    }
}

pub fn connection_row(fields: ConnectionRowFields) -> Result<TableRow, String> {
    let mut value = vec![0; ROW_VALUE_BYTES];
    value[0..32].copy_from_slice(&fields.from_endpoint);
    value[32..64].copy_from_slice(&fields.to_endpoint);
    value[64..96].copy_from_slice(&fields.request_id);
    value[96..128].copy_from_slice(&fields.responder_ephemeral_public_key);
    value[128..160].copy_from_slice(&fields.handshake_hash);
    value[160..192].copy_from_slice(&fields.connection_secret);
    value[192..192 + ADDR_BLOCK_BYTES]
        .copy_from_slice(&encode_optional_addr(fields.responder_addr)?);
    value[192 + ADDR_BLOCK_BYTES..192 + ADDR_BLOCK_BYTES + ADDR_BLOCK_BYTES]
        .copy_from_slice(&encode_optional_addr(fields.initiator_addr)?);
    Ok(TableRow {
        table: CONNECTION_ROWS,
        key: connection_key(&fields.connection_id),
        value,
    })
}

pub fn decode_connection_row(key: &[u8], value: &[u8]) -> Result<ConnectionRow, String> {
    if key.len() != 32 {
        return Err("connection row key must be the connection id".to_string());
    }
    if value.len() != ROW_VALUE_BYTES {
        return Err("connection row value is malformed".to_string());
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
    let mut addr_bytes = [0u8; ADDR_BLOCK_BYTES];
    addr_bytes.copy_from_slice(&value[192..192 + ADDR_BLOCK_BYTES]);
    let responder_addr = decode_optional_addr(&addr_bytes)?;
    addr_bytes
        .copy_from_slice(&value[192 + ADDR_BLOCK_BYTES..192 + ADDR_BLOCK_BYTES + ADDR_BLOCK_BYTES]);
    let initiator_addr = decode_optional_addr(&addr_bytes)?;
    Ok(ConnectionRow {
        connection_id,
        from_endpoint,
        to_endpoint,
        request_id,
        responder_ephemeral_public_key,
        handshake_hash,
        connection_secret,
        responder_addr,
        initiator_addr,
    })
}

pub fn answered_request_ids(store: &Store) -> Result<BTreeSet<FactId>, String> {
    let mut answered = BTreeSet::new();
    for (key, value) in store
        .table_rows(CONNECTION_ROWS)
        .map_err(|err| format!("read connection rows: {err}"))?
    {
        answered.insert(decode_connection_row(&key, &value)?.request_id);
    }
    Ok(answered)
}
