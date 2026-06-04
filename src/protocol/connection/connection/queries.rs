//! Read queries for materialized connections.
//!
//! These helpers expose live connection rows without making intent handlers
//! import row-table internals.

use crate::core::facts::FactId;
use crate::core::store::Store;

use super::rows::{connection_key, decode_connection_row, ConnectionRow, CONNECTION_ROWS};

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
