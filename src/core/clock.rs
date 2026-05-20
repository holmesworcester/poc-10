//! Store-local logical clock for deterministic CLI scenarios.
//!
//! This is not a protocol event and it is not synced. It is local operator/test
//! metadata used as a lower bound when CLI commands choose the next event
//! timestamp. Existing event timestamps still win, so setting the clock
//! backwards cannot make new shared events collide with old ones.

use crate::core::store::{Store, TableName, TableRow};

const CLOCK_TABLE: TableName = TableName::new("clock");

const CLOCK_KEY: &[u8] = b"now";

pub fn logical_time(store: &Store) -> Result<Option<u64>, String> {
    store
        .table_row(CLOCK_TABLE, CLOCK_KEY)
        .map_err(|err| format!("load logical clock: {err}"))?
        .map(|value| decode_value(&value))
        .transpose()
}

pub fn set_logical_time(store: &Store, timestamp: u64) -> Result<u64, String> {
    store
        .write_transaction(|store| store.replace_table_rows_in_tx(vec![clock_row(timestamp)]))
        .map_err(|err| format!("set logical clock: {err}"))?;
    Ok(timestamp)
}

pub fn advance_logical_time(store: &Store, delta: u64) -> Result<u64, String> {
    let current = logical_time(store)?.unwrap_or(0);
    let next = current
        .checked_add(delta)
        .ok_or_else(|| "logical clock advance overflows u64".to_string())?;
    set_logical_time(store, next)
}

pub fn clear_logical_time(store: &Store) -> Result<(), String> {
    store
        .delete_table_rows(CLOCK_TABLE, vec![CLOCK_KEY.to_vec()])
        .map_err(|err| format!("clear logical clock: {err}"))?;
    Ok(())
}

pub fn next_timestamp(store: &Store, observed_max_timestamp: u64) -> Result<u64, String> {
    let from_events = observed_max_timestamp.saturating_add(1);
    Ok(from_events.max(logical_time(store)?.unwrap_or(0)))
}

fn clock_row(timestamp: u64) -> TableRow {
    TableRow {
        table: CLOCK_TABLE,
        key: CLOCK_KEY.to_vec(),
        value: timestamp.to_be_bytes().to_vec(),
    }
}

fn decode_value(value: &[u8]) -> Result<u64, String> {
    let bytes: [u8; 8] = value
        .try_into()
        .map_err(|_| format!("logical clock row should be 8 bytes, got {}", value.len()))?;
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_is_a_lower_bound_for_next_timestamp() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema_dsl::CORE_SCHEMA_SOURCE])
                .expect("store");

        assert_eq!(next_timestamp(&store, 7).expect("next"), 8);

        set_logical_time(&store, 100).expect("set");
        assert_eq!(next_timestamp(&store, 7).expect("next"), 100);
        assert_eq!(next_timestamp(&store, 125).expect("next"), 126);
    }

    #[test]
    fn advance_and_clear_are_store_local() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema_dsl::CORE_SCHEMA_SOURCE])
                .expect("store");

        assert_eq!(advance_logical_time(&store, 5).expect("advance"), 5);
        assert_eq!(advance_logical_time(&store, 7).expect("advance"), 12);
        assert_eq!(logical_time(&store).expect("clock"), Some(12));

        clear_logical_time(&store).expect("clear");
        assert_eq!(logical_time(&store).expect("clock"), None);
    }
}
