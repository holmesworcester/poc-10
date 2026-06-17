//! Read queries for materialized connections.
//!
//! These helpers expose live connection rows without making intent handlers
//! import row-table internals.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::store::{Store, DEFAULT_QUERY_LIMIT};
use rusqlite::{params, OptionalExtension, Row};

use crate::protocol::auth;
use crate::protocol::connection::request::{
    encode::ADDR_BLOCK_BYTES, project::decode::decode_optional_addr,
};
use crate::protocol::connection::{
    close, ephemeral_secret, fact_receipt, frame_bundle, frame_file_slice, frame_observation,
    frame_small, request,
};

use super::EndpointId;

fn addr_block(value: Vec<u8>, name: &str) -> rusqlite::Result<[u8; ADDR_BLOCK_BYTES]> {
    value.as_slice().try_into().map_err(|_| {
        rusqlite::Error::InvalidParameterName(format!("connection row {name} block is malformed"))
    })
}

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

pub fn decode_connection_row(row: &Row<'_>) -> rusqlite::Result<ConnectionRow> {
    let responder_addr = decode_optional_addr(&addr_block(row.get(6)?, "responder_addr")?)
        .map_err(rusqlite::Error::InvalidParameterName)?;
    let initiator_addr = decode_optional_addr(&addr_block(row.get(7)?, "initiator_addr")?)
        .map_err(rusqlite::Error::InvalidParameterName)?;
    Ok(ConnectionRow {
        connection_id: row.get(0)?,
        from_endpoint: row.get(1)?,
        to_endpoint: row.get(2)?,
        request_id: row.get(3)?,
        responder_ephemeral_public_key: row.get(4)?,
        handshake_hash: row.get(5)?,
        connection_secret: row.get(8)?,
        responder_addr,
        initiator_addr,
    })
}

pub fn answered_request_ids(store: &Store) -> Result<BTreeSet<FactId>, String> {
    let mut answered = BTreeSet::new();
    for row in connection_rows(store)? {
        answered.insert(row.request_id);
    }
    Ok(answered)
}

pub fn connection_rows(store: &Store) -> Result<Vec<ConnectionRow>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT connection_id,
                    from_endpoint,
                    to_endpoint,
                    request_id,
                    responder_ephemeral_public_key,
                    handshake_hash,
                    responder_addr,
                    initiator_addr,
                    connection_secret
             FROM connection_rows
             ORDER BY connection_id
             LIMIT ?1",
        )
        .map_err(|err| format!("read connection rows: {err}"))?;
    let rows = stmt
        .query_map(params![DEFAULT_QUERY_LIMIT as i64], decode_connection_row)
        .map_err(|err| format!("read connection rows: {err}"))?;
    rows.collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("decode connection rows: {err}"))
}

pub fn connection_by_id(
    store: &Store,
    connection_id: &FactId,
) -> Result<Option<ConnectionRow>, String> {
    store
        .conn()
        .query_row(
            "SELECT connection_id,
                    from_endpoint,
                    to_endpoint,
                    request_id,
                    responder_ephemeral_public_key,
                    handshake_hash,
                    responder_addr,
                    initiator_addr,
                    connection_secret
             FROM connection_rows
             WHERE connection_id = ?1
             LIMIT 1",
            params![connection_id],
            decode_connection_row,
        )
        .optional()
        .map_err(|err| format!("read connection row: {err}"))
}

pub fn has_connection_between(
    store: &Store,
    left_endpoint: FactId,
    right_endpoint: FactId,
) -> Result<bool, String> {
    for row in connection_rows(store)? {
        if (row.from_endpoint == left_endpoint && row.to_endpoint == right_endpoint)
            || (row.from_endpoint == right_endpoint && row.to_endpoint == left_endpoint)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn sendable_fact_body(fact: &Fact) -> Result<&[u8], String> {
    if fact.scope == FactScope::Local {
        return Err(format!(
            "connection::frame send refused local fact {:?}",
            fact.id
        ));
    }

    let tag = fact
        .bytes
        .first()
        .copied()
        .ok_or_else(|| format!("connection::frame send refused empty fact {:?}", fact.id))?;
    if is_private_local_fact_tag(tag) {
        return Err(format!(
            "connection::frame send refused private/local fact tag {tag} for {:?}",
            fact.id
        ));
    }

    Ok(fact.body())
}

fn is_private_local_fact_tag(tag: u8) -> bool {
    matches!(
        tag,
        close::encode::TYPE_CONNECTION_CLOSE
            | ephemeral_secret::encode::TYPE_CONNECTION_EPHEMERAL_SECRET
            | request::encode::TYPE_CONNECTION_REQUEST
            | super::encode::TYPE_CONNECTION
            | auth::endpoint::encode::TYPE_LOCAL_ENDPOINT
            | auth::invite_secret::encode::TYPE_INVITE_SECRET
            | auth::local_signer_secret::encode::TYPE_LOCAL_SIGNER_SECRET
            | auth::local_key_secret::encode::TYPE_LOCAL_KEY_SECRET
            | auth::local_history_node_secret::encode::TYPE_LOCAL_HISTORY_NODE_SECRET
            | auth::local_recipient_key::encode::TYPE_LOCAL_RECIPIENT_KEY
            | frame_small::encode::TYPE_CONNECTION_FRAME_SMALL
            | frame_file_slice::encode::TYPE_CONNECTION_FRAME_FILE_SLICE
            | frame_bundle::encode::TYPE_CONNECTION_FRAME_BUNDLE
            | frame_observation::encode::TYPE_CONNECTION_FRAME_OBSERVATION
            | fact_receipt::encode::TYPE_CONNECTION_FACT_RECEIPT
    )
}
