//! Read-only decoding and lookups for connection fact-receipt origin rows.
//!
//! These rows are a narrow efficiency hint for sync live-tail egress. They say
//! which established connection delivered a fact when that is known; they do not
//! authorize the received payload or replace projector receipt validation.
//! Query helpers decode that row state and never write, construct facts,
//! project, or dispatch intents.

use crate::core::facts::FactId;
use crate::core::store::{Store, DEFAULT_QUERY_LIMIT};
use rusqlite::{params, Row};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionFactReceiptRow {
    pub received_fact_id: FactId,
    pub receipt_fact_id: FactId,
    pub connection_id: Option<FactId>,
}

pub fn decode_connection_fact_receipt_row(
    row: &Row<'_>,
) -> rusqlite::Result<ConnectionFactReceiptRow> {
    let raw_connection_id = row.get(3)?;
    let connection_id = match row.get::<_, i64>(2)? {
        0 => {
            if raw_connection_id != [0; 32] {
                return Err(rusqlite::Error::InvalidParameterName(
                    "connection fact receipt row none connection must be zero".to_string(),
                ));
            }
            None
        }
        1 => Some(raw_connection_id),
        _ => {
            return Err(rusqlite::Error::InvalidParameterName(
                "invalid connection fact receipt row connection flag".to_string(),
            ))
        }
    };
    Ok(ConnectionFactReceiptRow {
        received_fact_id: row.get(0)?,
        receipt_fact_id: row.get(1)?,
        connection_id,
    })
}

pub fn origin_connection_ids_for_fact(
    store: &Store,
    received_fact_id: FactId,
) -> Result<Vec<FactId>, String> {
    let mut stmt = store
        .conn()
        .prepare(
            "SELECT received_fact_id,
                    receipt_fact_id,
                    has_connection,
                    connection_id
             FROM connection_fact_receipt_rows
             WHERE received_fact_id = ?1
             ORDER BY receipt_fact_id
             LIMIT ?2",
        )
        .map_err(|err| format!("load connection fact receipt rows: {err}"))?;
    let rows = stmt
        .query_map(
            params![received_fact_id, DEFAULT_QUERY_LIMIT as i64],
            decode_connection_fact_receipt_row,
        )
        .map_err(|err| format!("load connection fact receipt rows: {err}"))?;
    let mut ids = rows
        .map(|row| row.map(|row| row.connection_id))
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("decode connection fact receipt rows: {err}"))?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    Ok(ids)
}
