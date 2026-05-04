use std::{net::SocketAddr, str::FromStr};

use crate::core::store::Store;

use super::super::types::connection_id_from_bytes;
use super::tables;
use super::types::TransportRoute;

pub fn routes(store: &Store) -> Result<Vec<TransportRoute>, String> {
    let rows = store
        .table_rows(tables::TRANSPORT_TARGETS)
        .map_err(|err| format!("load transport targets: {err}"))?;
    rows.into_iter()
        .map(|(key, value)| {
            let connection_id = connection_id_from_bytes(&key)?;
            let text = String::from_utf8(value)
                .map_err(|err| format!("transport target is not utf8: {err}"))?;
            let addr = SocketAddr::from_str(&text)
                .map_err(|err| format!("transport target is invalid: {err}"))?;
            Ok(TransportRoute {
                connection_id,
                addr,
            })
        })
        .collect()
}
