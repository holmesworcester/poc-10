//! Intent queue row codec and writes.
//!
//! Queue tables own intent durability. The row format is shared by durable and
//! restart-local queues; callers choose the destination table.

use crate::core::intents::{Intent, IntentKind};
use crate::core::schema::INTENTS;
use crate::core::store::{Store, TableName, TableRow};
use crate::core::wire::{Reader, WireError, Writer};

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
    let mut row = intent_row(intent);
    row.table = table;
    store
        .insert_table_rows_in_tx(vec![row])
        .map(|count| count > 0)
}

/// Key layout for an intent queue row: `kind ++ idempotence-key`.
///
/// Two intents collide here exactly when they are idempotent duplicates of each
/// other. The queue table determines durable versus restart-local storage.
pub(crate) fn intent_row_key(intent: &Intent) -> Vec<u8> {
    encoded_row(|key| {
        key.string_u32be(intent.kind.as_str())
            .expect("intent kind fits u32");
        key.bytes_u32be(&intent.key)
            .expect("intent idempotence key fits u32");
    })
}

/// Decode an intent queue row: kind and idempotence key from the key, payload
/// from the value.
pub(crate) fn decode_intent_row(key: &[u8], value: &[u8]) -> Result<Intent, String> {
    let mut key_reader = Reader::new(key);
    let kind = IntentKind::new(key_reader.string_u32be().row()?)?;
    let idempotence_key = key_reader.bytes_u32be().row()?.to_vec();
    key_reader.finish().row()?;

    let mut value_reader = Reader::new(value);
    let payload = value_reader.bytes_u32be().row()?.to_vec();
    value_reader.finish().row()?;
    Ok(Intent::new(kind, idempotence_key, payload))
}

fn intent_row(intent: &Intent) -> TableRow {
    TableRow {
        table: INTENTS,
        key: intent_row_key(intent),
        value: typed_intent_value(intent),
    }
}

fn typed_intent_value(intent: &Intent) -> Vec<u8> {
    encoded_row(|out| {
        out.bytes_u32be(&intent.payload)
            .expect("intent payload fits u32");
    })
}

fn encoded_row(write: impl FnOnce(&mut Writer)) -> Vec<u8> {
    let mut out = Writer::new();
    write(&mut out);
    out.finish()
}

trait RowWireResult<T> {
    fn row(self) -> Result<T, String>;
}

impl<T> RowWireResult<T> for Result<T, WireError> {
    fn row(self) -> Result<T, String> {
        self.map_err(|err| format!("invalid encoded row: {err}"))
    }
}
