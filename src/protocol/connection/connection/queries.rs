//! Read queries for materialized connections.
//!
//! These helpers expose live connection rows without making intent handlers
//! import row-table internals.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use crate::core::facts::FactId;
use crate::core::store::Store;

use crate::protocol::connection::request::{
    decode::decode_optional_addr, encode::ADDR_BLOCK_BYTES,
};

use super::{connection_key, EndpointId, CONNECTION_ROWS, CONNECTION_ROW_SCHEMA};

fn addr_block(
    value: &crate::core::row_schema::RowValue,
    name: &str,
) -> Result<[u8; ADDR_BLOCK_BYTES], String> {
    value
        .as_bytes(name)?
        .try_into()
        .map_err(|_| format!("connection row {name} block is malformed"))
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

pub fn decode_connection_row(key: &[u8], value: &[u8]) -> Result<ConnectionRow, String> {
    let key_fields = CONNECTION_ROW_SCHEMA.decode_key(key)?;
    let value_fields = CONNECTION_ROW_SCHEMA.decode_value(value)?;
    let responder_addr = decode_optional_addr(&addr_block(&value_fields[6], "responder_addr")?)?;
    let initiator_addr = decode_optional_addr(&addr_block(&value_fields[7], "initiator_addr")?)?;
    Ok(ConnectionRow {
        connection_id: key_fields[0].as_bytes32("connection_id")?,
        from_endpoint: value_fields[0].as_bytes32("from_endpoint")?,
        to_endpoint: value_fields[1].as_bytes32("to_endpoint")?,
        request_id: value_fields[2].as_bytes32("request_id")?,
        responder_ephemeral_public_key: value_fields[3]
            .as_bytes32("responder_ephemeral_public_key")?,
        handshake_hash: value_fields[4].as_bytes32("handshake_hash")?,
        connection_secret: value_fields[5].as_bytes32("connection_secret")?,
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

pub fn connection_by_id(
    store: &Store,
    connection_id: &FactId,
) -> Result<Option<ConnectionRow>, String> {
    let row = store
        .table_row(CONNECTION_ROWS, &connection_key(connection_id))
        .map_err(|err| format!("read connection row: {err}"))?;
    row.map(|value| decode_connection_row(connection_id, &value))
        .transpose()
}

pub fn has_connection_between(
    store: &Store,
    left_endpoint: FactId,
    right_endpoint: FactId,
) -> Result<bool, String> {
    for (key, value) in store
        .table_rows(CONNECTION_ROWS)
        .map_err(|err| format!("read connection rows: {err}"))?
    {
        let row = decode_connection_row(&key, &value)?;
        if (row.from_endpoint == left_endpoint && row.to_endpoint == right_endpoint)
            || (row.from_endpoint == right_endpoint && row.to_endpoint == left_endpoint)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::connection::connection::ConnectionRowFields;

    #[test]
    fn connection_row_roundtrips_through_schema() {
        let fields = ConnectionRowFields {
            connection_id: [1; 32],
            from_endpoint: [2; 32],
            to_endpoint: [3; 32],
            request_id: [4; 32],
            responder_ephemeral_public_key: [5; 32],
            handshake_hash: [6; 32],
            connection_secret: [7; 32],
            responder_addr: Some("127.0.0.1:41002".parse().unwrap()),
            initiator_addr: Some("127.0.0.1:41001".parse().unwrap()),
        };
        let row = super::super::connection_row(fields).expect("connection row");
        let decoded = decode_connection_row(&row.key, &row.value).expect("decode connection row");
        assert_eq!(decoded.connection_id, [1; 32]);
        assert_eq!(decoded.from_endpoint, [2; 32]);
        assert_eq!(decoded.to_endpoint, [3; 32]);
        assert_eq!(decoded.request_id, [4; 32]);
        assert_eq!(decoded.responder_ephemeral_public_key, [5; 32]);
        assert_eq!(decoded.handshake_hash, [6; 32]);
        assert_eq!(decoded.connection_secret, [7; 32]);
        assert_eq!(
            decoded.responder_addr,
            Some("127.0.0.1:41002".parse().unwrap())
        );
        assert_eq!(
            decoded.initiator_addr,
            Some("127.0.0.1:41001".parse().unwrap())
        );
    }
}
