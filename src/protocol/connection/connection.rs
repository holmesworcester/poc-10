//! Unified connection fact family.
//!
//! A connection completes a bootstrap or membership handshake. The same sealed
//! fact is sent by the responder and projected by both parties; its fact id is
//! the connection id and projection writes the live connection row used by frame
//! and sync routing.

pub mod adapt;
pub mod authenticate;
pub mod author;
pub mod decode;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

use std::net::SocketAddr;

use crate::core::facts::FactId;
use crate::core::row_schema::{RowField, RowTableSchema, RowValue};
use crate::core::store::{TableName, TableRow};

use crate::protocol::connection::request::encode::{encode_optional_addr, ADDR_BLOCK_BYTES};

pub type EndpointId = FactId;

/// Durable rows for materialized connections, keyed by the connection fact id.
pub const CONNECTION_ROWS: TableName = TableName::new("connection_rows");

const CONNECTION_ROW_KEY_FIELDS: &[RowField] = &[RowField::bytes32("connection_id")];
const CONNECTION_ROW_VALUE_FIELDS: &[RowField] = &[
    RowField::bytes32("from_endpoint"),
    RowField::bytes32("to_endpoint"),
    RowField::bytes32("request_id"),
    RowField::bytes32("responder_ephemeral_public_key"),
    RowField::bytes32("handshake_hash"),
    RowField::bytes32("connection_secret"),
    RowField::bytes("responder_addr", ADDR_BLOCK_BYTES),
    RowField::bytes("initiator_addr", ADDR_BLOCK_BYTES),
];

pub const CONNECTION_ROW_SCHEMA: RowTableSchema = RowTableSchema::new(
    CONNECTION_ROWS,
    CONNECTION_ROW_KEY_FIELDS,
    CONNECTION_ROW_VALUE_FIELDS,
);

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
    CONNECTION_ROW_SCHEMA.row(
        &[RowValue::Bytes(fields.connection_id.to_vec())],
        &[
            RowValue::Bytes(fields.from_endpoint.to_vec()),
            RowValue::Bytes(fields.to_endpoint.to_vec()),
            RowValue::Bytes(fields.request_id.to_vec()),
            RowValue::Bytes(fields.responder_ephemeral_public_key.to_vec()),
            RowValue::Bytes(fields.handshake_hash.to_vec()),
            RowValue::Bytes(fields.connection_secret.to_vec()),
            RowValue::Bytes(encode_optional_addr(fields.responder_addr)?.to_vec()),
            RowValue::Bytes(encode_optional_addr(fields.initiator_addr)?.to_vec()),
        ],
    )
}
