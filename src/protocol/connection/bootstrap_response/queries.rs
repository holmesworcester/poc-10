//! Read queries for materialized connection responses.
//!
//! These helpers expose the shared live connection row without making intent
//! handlers import row-table internals.

use crate::core::facts::FactId;
use crate::core::store::Store;

use super::rows::{
    bootstrap_response_key, decode_bootstrap_response_row, BootstrapResponseRow,
    BOOTSTRAP_RESPONSE_ROWS,
};

pub fn connection_by_id(
    store: &Store,
    connection_id: &FactId,
) -> Result<Option<BootstrapResponseRow>, String> {
    let row = store
        .table_row(
            BOOTSTRAP_RESPONSE_ROWS,
            &bootstrap_response_key(connection_id),
        )
        .map_err(|err| format!("read connection response row: {err}"))?;
    row.map(|value| decode_bootstrap_response_row(connection_id, &value))
        .transpose()
}
