//! Durable rows for local outbound membership connection requests.
//!
//! Only the local-outbound path writes a row. It carries the initiator
//! ephemeral-secret dependency id and the reachable `peer_addr`, so the live
//! `maintain_connections` loop can re-send an unanswered membership request the
//! same way it re-sends bootstrap requests. Received membership requests need no
//! row: the response is built from request context, and we never re-send a
//! request we received.
//!
//! Change this file for membership request row compatibility. Projection owns
//! when the row is written, and layout owns canonical request fact bytes.

use std::net::SocketAddr;

use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};

use crate::protocol::connection::bootstrap_request::create::{
    decode_optional_addr, encode_optional_addr, ADDR_BLOCK_BYTES,
};

pub const CONNECTION_REQUEST_ROWS: TableName = TableName::new("connection_request_rows");
pub const ROW_VALUE_BYTES: usize = 32 + ADDR_BLOCK_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionRequestRow {
    pub request_id: FactId,
    pub initiator_ephemeral_secret_fact_id: FactId,
    /// Reachable address to (re)send this membership request to. Always `Some`
    /// here: only the local outbound path writes a row.
    pub peer_addr: Option<SocketAddr>,
}

pub fn connection_request_key(request_id: &FactId) -> Vec<u8> {
    request_id.to_vec()
}

pub fn connection_request_row(
    request_id: FactId,
    initiator_ephemeral_secret_fact_id: FactId,
    peer_addr: Option<SocketAddr>,
) -> Result<TableRow, String> {
    let mut value = vec![0; ROW_VALUE_BYTES];
    value[0..32].copy_from_slice(&initiator_ephemeral_secret_fact_id);
    value[32..32 + ADDR_BLOCK_BYTES].copy_from_slice(&encode_optional_addr(peer_addr)?);
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
        return Err("membership connection request row key must be the request fact id".to_string());
    }
    if value.len() != ROW_VALUE_BYTES {
        return Err("membership connection request row value is malformed".to_string());
    }
    let mut request_id = [0; 32];
    request_id.copy_from_slice(key);
    let mut initiator_ephemeral_secret_fact_id = [0; 32];
    initiator_ephemeral_secret_fact_id.copy_from_slice(&value[0..32]);
    let mut addr_bytes = [0; ADDR_BLOCK_BYTES];
    addr_bytes.copy_from_slice(&value[32..32 + ADDR_BLOCK_BYTES]);
    let peer_addr = decode_optional_addr(&addr_bytes)?;
    Ok(ConnectionRequestRow {
        request_id,
        initiator_ephemeral_secret_fact_id,
        peer_addr,
    })
}
