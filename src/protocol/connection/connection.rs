//! Unified connection fact family.
//!
//! A connection completes a bootstrap or membership handshake. The same sealed
//! fact is sent by the responder and projected by both parties; its fact id is
//! the connection id and projection writes the live connection row used by frame
//! and sync routing.

pub mod author;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

use std::net::SocketAddr;

use crate::core::db::{TableInsert, TableName, TypedTableSchema, Value};
use crate::core::facts::FactId;

use crate::protocol::connection::request::encode::encode_optional_addr;

pub type EndpointId = FactId;

/// Durable rows for materialized connections, keyed by the connection fact id.
pub const CONNECTION_ROWS: TableName = TableName::new("connection_rows");

pub const CONNECTION_COLUMNS: &[&str] = &[
    "connection_id",
    "from_endpoint",
    "to_endpoint",
    "request_id",
    "responder_ephemeral_public_key",
    "handshake_hash",
    "connection_secret",
    "responder_addr",
    "initiator_addr",
];
pub const CONNECTION_KEY_COLUMNS: &[&str] = &["connection_id"];
pub const CONNECTION_TABLE: TypedTableSchema = TypedTableSchema {
    table: CONNECTION_ROWS,
    columns: CONNECTION_COLUMNS,
    key_columns: CONNECTION_KEY_COLUMNS,
};

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

pub fn connection_row(fields: ConnectionRowFields) -> Result<TableInsert, String> {
    Ok(CONNECTION_TABLE.insert(vec![
        Value::Bytes(fields.connection_id.to_vec()),
        Value::Bytes(fields.from_endpoint.to_vec()),
        Value::Bytes(fields.to_endpoint.to_vec()),
        Value::Bytes(fields.request_id.to_vec()),
        Value::Bytes(fields.responder_ephemeral_public_key.to_vec()),
        Value::Bytes(fields.handshake_hash.to_vec()),
        Value::Bytes(fields.connection_secret.to_vec()),
        Value::Bytes(encode_optional_addr(fields.responder_addr)?.to_vec()),
        Value::Bytes(encode_optional_addr(fields.initiator_addr)?.to_vec()),
    ]))
}
