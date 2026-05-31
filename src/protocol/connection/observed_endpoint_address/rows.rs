//! Observed endpoint-address rows.
//!
//! A learned-address row records the last reachable *listen* address observed
//! for a endpoint, keyed by endpoint id. It is written from the handshake
//! request projector (which carries each side's `listen_addr`), so it holds the
//! address an endpoint advertised for reconnection — not the ephemeral socket a frame
//! happened to arrive from. A membership connection resolves a known endpoint's
//! address from here, which is what lets reconnection survive an expired invite.
//!
//! Replacement semantics: keyed by endpoint id, last write wins. The projector
//! deletes any prior row for the endpoint and inserts the freshly observed
//! address. Change this file for learned-address row compatibility; the query
//! helper lives in `queries.rs` and the write is emitted by the request
//! projector.

use std::net::SocketAddr;

use crate::core::facts::FactId;
use crate::core::store::{TableName, TableRow};

use crate::protocol::connection::bootstrap_request::create as addr;

pub const CONNECTION_OBSERVED_ENDPOINT_ADDRESS_ROWS: TableName =
    TableName::new("connection_observed_endpoint_address_rows");

pub fn observed_endpoint_address_key(endpoint_id: &FactId) -> Vec<u8> {
    endpoint_id.to_vec()
}

pub fn observed_endpoint_address_row(endpoint_id: FactId, address: SocketAddr) -> Result<TableRow, String> {
    Ok(TableRow {
        table: CONNECTION_OBSERVED_ENDPOINT_ADDRESS_ROWS,
        key: observed_endpoint_address_key(&endpoint_id),
        value: addr::encode_optional_addr(Some(address))?.to_vec(),
    })
}

pub fn decode_observed_endpoint_address_row(key: &[u8], value: &[u8]) -> Result<(FactId, SocketAddr), String> {
    let endpoint_id: FactId = key
        .try_into()
        .map_err(|_| "peer address row key is not a 32-byte endpoint id".to_string())?;
    let addr_bytes: [u8; addr::ADDR_BLOCK_BYTES] = value
        .try_into()
        .map_err(|_| "peer address row value has wrong length".to_string())?;
    let address = addr::decode_optional_addr(&addr_bytes)?
        .ok_or_else(|| "peer address row has no address".to_string())?;
    Ok((endpoint_id, address))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observed_endpoint_address_row_roundtrips() {
        let addr: SocketAddr = "127.0.0.1:41001".parse().unwrap();
        let row = observed_endpoint_address_row([7; 32], addr).expect("encode");
        let (endpoint, decoded) = decode_observed_endpoint_address_row(&row.key, &row.value).expect("decode");
        assert_eq!(endpoint, [7; 32]);
        assert_eq!(decoded, addr);
    }
}
