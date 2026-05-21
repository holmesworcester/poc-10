//! Store-local logical clock for deterministic CLI scenarios.
//!
//! This is not a protocol event and it is not synced. It is local operator/test
//! metadata used as a lower bound when CLI commands choose the next event
//! timestamp. Existing event timestamps still win, so setting the clock
//! backwards cannot make new shared events collide with old ones.

use crate::core::cli::{CliArgs, CliOutput};
use crate::core::store::{Store, TableName, TableRow};

const CLOCK_TABLE: TableName = TableName::new("clock");

const CLOCK_KEY: &[u8] = b"now";

pub const CLOCK_USAGE: &str = "clock [set TIMESTAMP|advance DELTA|clear]";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockReport {
    pub logical_time: Option<u64>,
    pub max_event_timestamp: u64,
    pub next_timestamp: u64,
}

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

pub fn run_cli(
    store: &Store,
    args: CliArgs<'_>,
    observed_max_timestamp: u64,
) -> Result<CliOutput, String> {
    let report = apply_cli_args(store, args, observed_max_timestamp)?;
    Ok(clock_report_output(&report))
}

pub fn apply_cli_args(
    store: &Store,
    args: CliArgs<'_>,
    observed_max_timestamp: u64,
) -> Result<ClockReport, String> {
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
    Ok(ClockReport {
        logical_time,
        max_event_timestamp: observed_max_timestamp,
        next_timestamp,
    })
}

pub fn clock_report_output(report: &ClockReport) -> CliOutput {
    let logical_time = report
        .logical_time
        .map(|timestamp| timestamp.to_string())
        .unwrap_or_else(|| "unset".to_string());
    CliOutput::lines(vec![
        format!("logical_time: {logical_time}"),
        format!("max_event_timestamp: {}", report.max_event_timestamp),
        format!("next_timestamp: {}", report.next_timestamp),
    ])
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
