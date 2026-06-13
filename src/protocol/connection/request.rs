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

pub mod author;
pub mod commands;
pub mod encode;
pub mod fact;
pub mod project;
pub mod queries;

use crate::core::facts::FactId;
use crate::core::row_schema::{RowField, RowTableSchema, RowValue};
use crate::core::store::{TableName, TableRow};

use std::net::SocketAddr;

use crate::protocol::connection::request::encode::SEALED_FACT_BYTES;
use crate::protocol::connection::request::encode::{encode_optional_addr, ADDR_BLOCK_BYTES};

pub use project::{
    connection_for_request_need, connection_for_request_offer, connection_request_need,
    connection_request_offer,
};

/// Durable rows for local outbound connection requests, keyed by the request
/// fact id.
pub const CONNECTION_REQUEST_ROWS: TableName = TableName::new("connection_request_rows");
pub const BOOTSTRAP_CONNECTION_ATTEMPT_ROWS: TableName =
    TableName::new("bootstrap_connection_attempt_rows");

const CONNECTION_REQUEST_ROW_KEY_FIELDS: &[RowField] = &[RowField::bytes32("request_id")];
const CONNECTION_REQUEST_ROW_VALUE_FIELDS: &[RowField] = &[
    RowField::bytes32("request_sent_id"),
    RowField::bytes32("initiator_ephemeral_secret_fact_id"),
    RowField::bytes("peer_addr", ADDR_BLOCK_BYTES),
    RowField::bytes("sealed_request_bytes", SEALED_FACT_BYTES),
];

pub const CONNECTION_REQUEST_ROW_SCHEMA: RowTableSchema = RowTableSchema::new(
    CONNECTION_REQUEST_ROWS,
    CONNECTION_REQUEST_ROW_KEY_FIELDS,
    CONNECTION_REQUEST_ROW_VALUE_FIELDS,
);

const BOOTSTRAP_ATTEMPT_ROW_KEY_FIELDS: &[RowField] =
    &[RowField::bytes32("invite_accepted_fact_id")];
const BOOTSTRAP_ATTEMPT_ROW_VALUE_FIELDS: &[RowField] = &[RowField::bytes32("request_id")];

pub const BOOTSTRAP_CONNECTION_ATTEMPT_ROW_SCHEMA: RowTableSchema = RowTableSchema::new(
    BOOTSTRAP_CONNECTION_ATTEMPT_ROWS,
    BOOTSTRAP_ATTEMPT_ROW_KEY_FIELDS,
    BOOTSTRAP_ATTEMPT_ROW_VALUE_FIELDS,
);

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
        return Err("connection request row sealed bytes are malformed".to_string());
    }
    CONNECTION_REQUEST_ROW_SCHEMA.row(
        &[RowValue::Bytes(request_id.to_vec())],
        &[
            RowValue::Bytes(request_sent_id.to_vec()),
            RowValue::Bytes(initiator_ephemeral_secret_fact_id.to_vec()),
            RowValue::Bytes(encode_optional_addr(peer_addr)?.to_vec()),
            RowValue::Bytes(sealed_request_bytes.to_vec()),
        ],
    )
}

pub fn bootstrap_connection_attempt_row(
    invite_accepted_fact_id: FactId,
    request_id: FactId,
) -> Result<TableRow, String> {
    BOOTSTRAP_CONNECTION_ATTEMPT_ROW_SCHEMA.row(
        &[RowValue::Bytes(invite_accepted_fact_id.to_vec())],
        &[RowValue::Bytes(request_id.to_vec())],
    )
}
