//! Store-local logical clock for deterministic CLI scenarios.
//!
//! This is not protocol data and it is not synced. It is local operator/test
//! metadata used as a lower bound when CLI commands choose the next authored
//! timestamp. Existing authored timestamps still win, so setting the clock
//! backwards cannot make new shared facts collide with old ones.
//!
//! Change this file when the local CLI clock policy changes. Do not use it as
//! a shared protocol clock: facts and projected rows must carry their own
//! protocol-defined time semantics.

use crate::core::cli::{CliArgs, CliOutput};
use crate::core::store::Store;
use rusqlite::{params, OptionalExtension};

const CLOCK_KEY: &str = "now";

pub const CLOCK_USAGE: &str = "clock [set TIMESTAMP|advance DELTA|clear]";

/// Return the store-local logical clock, if one has been set.
pub fn logical_time(store: &Store) -> Result<Option<u64>, String> {
    store
        .conn()
        .query_row(
            "SELECT timestamp FROM clock WHERE key = ?1 LIMIT 1",
            params![CLOCK_KEY],
            |row| u64_column(row.get::<_, i64>(0)?, "timestamp"),
        )
        .optional()
        .map_err(|err| format!("load logical clock: {err}"))
}

/// Set the store-local logical clock and return the stored timestamp.
///
/// The value must fit SQLite's signed integer range because the table stores it
/// as `INTEGER`.
pub fn set_logical_time(store: &Store, timestamp: u64) -> Result<u64, String> {
    let timestamp = sqlite_u64(timestamp, "logical clock timestamp")?;
    store
        .write_transaction(|store| {
            store.conn().execute(
                "INSERT OR REPLACE INTO clock (key, timestamp) VALUES (?1, ?2)",
                params![CLOCK_KEY, timestamp],
            )
        })
        .map_err(|err| format!("set logical clock: {err}"))?;
    Ok(timestamp as u64)
}

/// Advance the store-local logical clock from its current value or zero.
pub fn advance_logical_time(store: &Store, delta: u64) -> Result<u64, String> {
    let current = logical_time(store)?.unwrap_or(0);
    let next = current
        .checked_add(delta)
        .ok_or_else(|| "logical clock advance overflows u64".to_string())?;
    set_logical_time(store, next)
}

/// Clear the store-local logical clock.
pub fn clear_logical_time(store: &Store) -> Result<(), String> {
    store
        .write_transaction(|store| {
            store
                .conn()
                .execute("DELETE FROM clock WHERE key = ?1", params![CLOCK_KEY])
        })
        .map_err(|err| format!("clear logical clock: {err}"))?;
    Ok(())
}

/// Compute the next timestamp a command should use.
///
/// The result is at least one greater than the observed authored maximum and at
/// least the local logical clock. This makes the clock a lower bound rather
/// than a source of truth that can override already-observed authored facts.
pub fn next_timestamp(store: &Store, observed_max_timestamp: u64) -> Result<u64, String> {
    let from_observed = observed_max_timestamp.saturating_add(1);
    Ok(from_observed.max(logical_time(store)?.unwrap_or(0)))
}

/// Run the generic `clock` CLI command against a store.
pub fn run_cli(
    store: &Store,
    args: CliArgs<'_>,
    observed_max_timestamp: u64,
) -> Result<CliOutput, String> {
    apply_cli_args(store, args, observed_max_timestamp)
}

fn apply_cli_args(
    store: &Store,
    args: CliArgs<'_>,
    observed_max_timestamp: u64,
) -> Result<CliOutput, String> {
    match args.values() {
        [] => {}
        [command, value] if command == "set" => {
            let timestamp = value
                .parse::<u64>()
                .map_err(|_| "clock set requires a u64 timestamp".to_string())?;
            set_logical_time(store, timestamp)?;
        }
        [command, value] if command == "advance" => {
            let delta = value
                .parse::<u64>()
                .map_err(|_| "clock advance requires a u64 delta".to_string())?;
            advance_logical_time(store, delta)?;
        }
        [command] if command == "clear" => {
            clear_logical_time(store)?;
        }
        _ => return Err(format!("clock usage: {CLOCK_USAGE}")),
    }

    let logical_time = logical_time(store)?;
    let next_timestamp = next_timestamp(store, observed_max_timestamp)?;
    let logical_time = logical_time
        .map(|timestamp| timestamp.to_string())
        .unwrap_or_else(|| "unset".to_string());
    Ok(CliOutput::lines(vec![
        format!("logical_time: {logical_time}"),
        format!("max_observed_timestamp: {observed_max_timestamp}"),
        format!("next_timestamp: {next_timestamp}"),
    ]))
}

fn u64_column(value: i64, name: &str) -> rusqlite::Result<u64> {
    u64::try_from(value)
        .map_err(|_| rusqlite::Error::InvalidParameterName(format!("{name} is negative")))
}

fn sqlite_u64(value: u64, name: &str) -> Result<i64, String> {
    i64::try_from(value).map_err(|_| format!("{name} exceeds SQLite integer range"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clock_is_a_lower_bound_for_next_timestamp() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("store");

        assert_eq!(next_timestamp(&store, 7).expect("next"), 8);

        set_logical_time(&store, 100).expect("set");
        assert_eq!(next_timestamp(&store, 7).expect("next"), 100);
        assert_eq!(next_timestamp(&store, 125).expect("next"), 126);
    }

    #[test]
    fn advance_and_clear_are_store_local() {
        let store =
            Store::open_memory_with_schema_sources(&[crate::core::schema::CORE_SCHEMA_SOURCE])
                .expect("store");

        assert_eq!(advance_logical_time(&store, 5).expect("advance"), 5);
        assert_eq!(advance_logical_time(&store, 7).expect("advance"), 12);
        assert_eq!(logical_time(&store).expect("clock"), Some(12));

        clear_logical_time(&store).expect("clear");
        assert_eq!(logical_time(&store).expect("clock"), None);
    }
}
