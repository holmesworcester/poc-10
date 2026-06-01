//! Durable rows for admitted connection requests.
//!
//! Rows are keyed by request fact id and store the endpoint pair, the invite,
//! invite-secret, and initiator ephemeral-secret dependency ids, plus the
//! reachable `peer_addr` to (re)send to. That compact row lets response
//! projection and diagnostics resolve request dependencies without re-decoding
//! the full fact body, and lets the live connection-maintenance loop find local
//! outbound requests that still need a send.
//!
//! `peer_addr` is `Some` only for a local outbound request that carries a route;
//! it is `None` for a received request. Maintenance re-sends only the local
//! outbound rows, so the address is the "this is ours to send" discriminator.
//!
//! Change this file for request row compatibility. Projection owns when the row
//! is written, and layout owns canonical request fact bytes.

use std::net::SocketAddr;

use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};

use super::create::{decode_optional_addr, encode_optional_addr, ADDR_BLOCK_BYTES};
use super::fact::{BootstrapRequestFact, EndpointId};

pub const BOOTSTRAP_REQUEST_ROWS: TableName = TableName::new("bootstrap_request_rows");
pub const ROW_VALUE_BYTES: usize = 32 + 32 + 32 + 32 + 32 + ADDR_BLOCK_BYTES;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootstrapRequestRow {
    pub request_id: FactId,
    pub from_endpoint: EndpointId,
    pub to_endpoint: EndpointId,
    pub invite_fact_id: FactId,
    pub invite_secret_fact_id: FactId,
    pub initiator_ephemeral_secret_fact_id: FactId,
    /// Reachable address to (re)send this request to. `Some` only for a local
    /// outbound request with a route; `None` for a received request, which the
    /// maintenance loop must never re-send.
    pub peer_addr: Option<SocketAddr>,
}

pub fn bootstrap_request_key(request_id: &FactId) -> Vec<u8> {
    request_id.to_vec()
}

pub fn bootstrap_request_row(
    request_id: FactId,
    fact: &BootstrapRequestFact,
    is_local_outbound: bool,
) -> Result<TableRow, String> {
    // Only a local outbound request carries a peer address to send to; a received
    // request stores `None` so the maintenance loop never re-sends it.
    let peer_addr: Option<SocketAddr> = if is_local_outbound {
        fact.to_listen_addr
    } else {
        None
    };
    let mut value = vec![0; ROW_VALUE_BYTES];
    value[0..32].copy_from_slice(&fact.from_endpoint);
    value[32..64].copy_from_slice(&fact.to_endpoint);
    value[64..96].copy_from_slice(&fact.invite_fact_id);
    value[96..128].copy_from_slice(&fact.invite_secret_fact_id);
    value[128..160].copy_from_slice(&fact.initiator_ephemeral_secret_fact_id);
    value[160..160 + ADDR_BLOCK_BYTES].copy_from_slice(&encode_optional_addr(peer_addr)?);
    Ok(TableRow {
        table: BOOTSTRAP_REQUEST_ROWS,
        key: bootstrap_request_key(&request_id),
        value,
    })
}

pub fn decode_bootstrap_request_row(
    key: &[u8],
    value: &[u8],
) -> Result<BootstrapRequestRow, String> {
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
    let mut addr_bytes = [0; ADDR_BLOCK_BYTES];
    addr_bytes.copy_from_slice(&value[160..160 + ADDR_BLOCK_BYTES]);
    let peer_addr = decode_optional_addr(&addr_bytes)?;
    Ok(BootstrapRequestRow {
        request_id,
        from_endpoint,
        to_endpoint,
        invite_fact_id,
        invite_secret_fact_id,
        initiator_ephemeral_secret_fact_id,
        peer_addr,
    })
}
