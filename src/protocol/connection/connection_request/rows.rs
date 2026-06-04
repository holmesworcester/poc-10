//! Durable rows for local outbound membership connection requests.
//!
//! Only the local-outbound path writes a row. It carries the local
//! `connection_request_sent` fact id, initiator ephemeral-secret dependency id,
//! reachable `peer_addr`, and the exact sealed request bytes, so the live
//! `maintain_connections` loop can re-send an unanswered membership request
//! without a local protocol request fact.
//!
//! Change this file for membership request row compatibility. Projection owns
//! when the row is written, and layout owns canonical request fact bytes.

use std::net::SocketAddr;

use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};

use crate::protocol::connection::bootstrap_request::create::{
    decode_optional_addr, encode_optional_addr, ADDR_BLOCK_BYTES,
};
use crate::protocol::connection::connection_request::layout::SEALED_FACT_BYTES;

pub const CONNECTION_REQUEST_ROWS: TableName = TableName::new("connection_request_rows");
pub const ROW_VALUE_BYTES: usize = 32 + 32 + ADDR_BLOCK_BYTES + SEALED_FACT_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRequestRow {
    pub request_id: FactId,
    pub request_sent_id: FactId,
    pub initiator_ephemeral_secret_fact_id: FactId,
    /// Reachable address to (re)send this membership request to. Always `Some`
    /// here: only the local outbound path writes a row.
    pub peer_addr: Option<SocketAddr>,
    pub sealed_request_bytes: Vec<u8>,
}

pub fn connection_request_key(request_id: &FactId) -> Vec<u8> {
    request_id.to_vec()
}

pub fn connection_request_row(
    request_id: FactId,
    request_sent_id: FactId,
    initiator_ephemeral_secret_fact_id: FactId,
    peer_addr: Option<SocketAddr>,
    sealed_request_bytes: &[u8],
) -> Result<TableRow, String> {
    if sealed_request_bytes.len() != SEALED_FACT_BYTES {
        return Err("membership connection request row sealed bytes are malformed".to_string());
    }
    let mut value = vec![0; ROW_VALUE_BYTES];
    value[0..32].copy_from_slice(&request_sent_id);
    value[32..64].copy_from_slice(&initiator_ephemeral_secret_fact_id);
    value[64..64 + ADDR_BLOCK_BYTES].copy_from_slice(&encode_optional_addr(peer_addr)?);
    value[64 + ADDR_BLOCK_BYTES..64 + ADDR_BLOCK_BYTES + SEALED_FACT_BYTES]
        .copy_from_slice(sealed_request_bytes);
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
        return Err(
            "membership connection request row key must be the request fact id".to_string(),
        );
    }
    if value.len() != ROW_VALUE_BYTES {
        return Err("membership connection request row value is malformed".to_string());
    }
    let mut request_id = [0; 32];
    request_id.copy_from_slice(key);
    let mut request_sent_id = [0; 32];
    request_sent_id.copy_from_slice(&value[0..32]);
    let mut initiator_ephemeral_secret_fact_id = [0; 32];
    initiator_ephemeral_secret_fact_id.copy_from_slice(&value[32..64]);
    let mut addr_bytes = [0; ADDR_BLOCK_BYTES];
    addr_bytes.copy_from_slice(&value[64..64 + ADDR_BLOCK_BYTES]);
    let peer_addr = decode_optional_addr(&addr_bytes)?;
    let sealed_request_bytes =
        value[64 + ADDR_BLOCK_BYTES..64 + ADDR_BLOCK_BYTES + SEALED_FACT_BYTES].to_vec();
    Ok(ConnectionRequestRow {
        request_id,
        request_sent_id,
        initiator_ephemeral_secret_fact_id,
        peer_addr,
        sealed_request_bytes,
    })
}
