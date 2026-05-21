//! Intent queue SQL writes and idempotence keys.
//!
//! Queue tables own intent durability. Durable and restart-local queues share
//! the same typed SQLite shape.

use crate::core::intents::Intent;
use crate::core::schema::{INTENTS, LOCAL_INTENTS};
use crate::core::store::{Store, TableName};
use rusqlite::{params, OptionalExtension};

/// Persist an intent to the durable queue, deduplicated by idempotence key.
pub(crate) fn record_intent_in_tx(store: &Store, intent: &Intent) -> rusqlite::Result<bool> {
    record_intent_in_table_in_tx(store, INTENTS, intent)
}

/// Persist an intent to `table`, deduplicated by idempotence key.
pub(crate) fn record_intent_in_table_in_tx(
    store: &Store,
    table: TableName,
    intent: &Intent,
) -> rusqlite::Result<bool> {
    let table_name = intent_table_name(table)?;
    let changed = store.conn().execute(
        &format!(
            "INSERT OR IGNORE INTO {table_name} (kind, idempotence_key, payload)
             VALUES (?1, ?2, ?3)"
        ),
        params![
            intent.kind.as_str(),
            intent.key.as_slice(),
            intent.payload.as_slice()
        ],
    )?;
    if changed == 0 {
        let existing = store
            .conn()
            .query_row(
                &format!(
                    "SELECT payload
                     FROM {table_name}
                     WHERE kind = ?1 AND idempotence_key = ?2"
                ),
                params![intent.kind.as_str(), intent.key.as_slice()],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .optional()?;
        if existing.as_deref() != Some(intent.payload.as_slice()) {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "conflicting intent row for {}",
                intent.kind.as_str()
            )));
        }
    }
    Ok(changed > 0)
}

fn intent_table_name(table: TableName) -> rusqlite::Result<&'static str> {
    if table == INTENTS {
        Ok("\"intents\"")
    } else if table == LOCAL_INTENTS {
        Ok("\"local_intents\"")
    } else {
        Err(rusqlite::Error::InvalidParameterName(format!(
            "table {} is not an intent queue",
            table.as_str()
        )))
    }
}
