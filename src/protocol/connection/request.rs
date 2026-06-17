//! Unified connection request family.
//!
//! A connection request is first contact for either bootstrap or membership
//! mode. Bootstrap mode is authorized by invite proof; membership mode is
//! authorized by `endpoint_shared` membership. Local commands construct the
//! sealed request fact, received network bytes are admitted as that same fact,
//! and projection validates the selected authority path before offering request
//! context or scheduling response work.
//!
//! This family owns request payload bytes, canonical request signature bytes, and request
//! admission policy. Response creation, frame sending, and socket IO belong to
//! the downstream connection modules.

pub mod api;
pub mod author;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

use crate::core::facts::FactId;
use crate::core::store::{TableInsert, TableName, TypedTableSchema, Value};

use std::net::SocketAddr;

use crate::protocol::connection::request::encode::encode_optional_addr;
use crate::protocol::connection::request::encode::SEALED_FACT_BYTES;

pub use project::{
    connection_for_request_need, connection_for_request_offer, connection_request_need,
    connection_request_offer,
};

/// Durable rows for local outbound connection requests, keyed by the request
/// fact id.
pub const CONNECTION_REQUEST_ROWS: TableName = TableName::new("connection_request_rows");
pub const BOOTSTRAP_CONNECTION_ATTEMPT_ROWS: TableName =
    TableName::new("bootstrap_connection_attempt_rows");

pub const CONNECTION_REQUEST_COLUMNS: &[&str] = &[
    "request_id",
    "request_sent_id",
    "initiator_ephemeral_secret_fact_id",
    "peer_addr",
    "sealed_request_bytes",
];
pub const CONNECTION_REQUEST_KEY_COLUMNS: &[&str] = &["request_id"];
pub const CONNECTION_REQUEST_TABLE: TypedTableSchema = TypedTableSchema {
    table: CONNECTION_REQUEST_ROWS,
    columns: CONNECTION_REQUEST_COLUMNS,
    key_columns: CONNECTION_REQUEST_KEY_COLUMNS,
};

pub const BOOTSTRAP_CONNECTION_ATTEMPT_COLUMNS: &[&str] =
    &["invite_accepted_fact_id", "request_id"];
pub const BOOTSTRAP_CONNECTION_ATTEMPT_KEY_COLUMNS: &[&str] = &["invite_accepted_fact_id"];
pub const BOOTSTRAP_CONNECTION_ATTEMPT_TABLE: TypedTableSchema = TypedTableSchema {
    table: BOOTSTRAP_CONNECTION_ATTEMPT_ROWS,
    columns: BOOTSTRAP_CONNECTION_ATTEMPT_COLUMNS,
    key_columns: BOOTSTRAP_CONNECTION_ATTEMPT_KEY_COLUMNS,
};

pub fn connection_request_key(request_id: &FactId) -> Vec<u8> {
    request_id.to_vec()
}

pub fn connection_request_row(
    request_id: FactId,
    request_sent_id: FactId,
    initiator_ephemeral_secret_fact_id: FactId,
    peer_addr: Option<SocketAddr>,
    sealed_request_bytes: &[u8],
) -> Result<TableInsert, String> {
    if sealed_request_bytes.len() != SEALED_FACT_BYTES {
        return Err("connection request row sealed bytes are malformed".to_string());
    }
    Ok(CONNECTION_REQUEST_TABLE.insert(vec![
        Value::Bytes(request_id.to_vec()),
        Value::Bytes(request_sent_id.to_vec()),
        Value::Bytes(initiator_ephemeral_secret_fact_id.to_vec()),
        Value::Bytes(encode_optional_addr(peer_addr)?.to_vec()),
        Value::Bytes(sealed_request_bytes.to_vec()),
    ]))
}

pub fn bootstrap_connection_attempt_row(
    invite_accepted_fact_id: FactId,
    request_id: FactId,
) -> Result<TableInsert, String> {
    Ok(BOOTSTRAP_CONNECTION_ATTEMPT_TABLE.insert(vec![
        Value::Bytes(invite_accepted_fact_id.to_vec()),
        Value::Bytes(request_id.to_vec()),
    ]))
}
