//! Local sync setting facts and read model.
//!
//! The sync setting is local-only operational state. Commands author local
//! facts, projection records one row per setting fact, and daemon sync reads the
//! latest projected row. No user command queues sync work directly.

use crate::core::cli::{encode_hex_32, CliArgs, CliOutput};
use crate::core::command::{CommandClock, CommandOutput};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::RowMutation;
use crate::core::project_fact::{
    verify_fact_id, FactProjectorInfo, ProjectionContext, ProjectionOutput, Projector,
};
use crate::core::row_schema::{RowField, RowTableSchema, RowValue};
use crate::core::store::{Store, TableName, TableRow};

use super::compare::fact::TimestampRange;

pub const TYPE_SYNC_LOCAL_SETTING: u8 = 174;
pub const FACT_BYTES: usize = 1 + 1 + 8 + 8 + 8;
const MODE_ALL: u8 = 0;
const MODE_RANGE: u8 = 1;

pub const SYNC_USAGE: &str = "sync [show|all|range --start-ms START --end-ms END]";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncSettingMode {
    All,
    Range(TimestampRange),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncLocalSettingFact {
    pub effective_at_ms: u64,
    pub mode: SyncSettingMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncSettingRow {
    pub setting_fact_id: FactId,
    pub effective_at_ms: u64,
    pub mode: SyncSettingMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncSettingReceipt {
    pub setting_fact_id: FactId,
    pub effective_at_ms: u64,
    pub mode: SyncSettingMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncCliCommand {
    Show,
    Set(SyncSettingMode),
}

/// Projector route metadata for the sync local setting fact.
pub const PROJECTOR_INFO: FactProjectorInfo =
    FactProjectorInfo::projector("sync::local_setting::SyncLocalSettingProjector");

/// Projected sync settings keyed by setting fact id. Queries resolve the active
/// row with `(effective_at_ms, setting_fact_id)` ordering.
pub const SYNC_LOCAL_SETTING_ROWS: TableName = TableName::new("sync_local_setting_rows");

const SYNC_LOCAL_SETTING_ROW_KEY_FIELDS: &[RowField] = &[RowField::bytes32("setting_fact_id")];
const SYNC_LOCAL_SETTING_ROW_VALUE_FIELDS: &[RowField] = &[
    RowField::u8("mode"),
    RowField::u64be("effective_at_ms"),
    RowField::u64be("start_ms"),
    RowField::u64be("end_ms"),
];

pub const SYNC_LOCAL_SETTING_ROW_SCHEMA: RowTableSchema = RowTableSchema::new(
    SYNC_LOCAL_SETTING_ROWS,
    SYNC_LOCAL_SETTING_ROW_KEY_FIELDS,
    SYNC_LOCAL_SETTING_ROW_VALUE_FIELDS,
);

#[derive(Debug, Clone, Default)]
pub struct SyncLocalSettingProjector;

impl SyncLocalSettingProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SyncLocalSettingProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let decoded = decode_fact(fact.body())?;
        let setting = authenticate(fact, decoded, context)?;
        if fact.scope != FactScope::Local {
            return Err("sync local setting fact must have local scope".to_string());
        }
        Ok(ProjectionOutput::new()
            .row_mutation(RowMutation::PutRow(setting_row(fact.id, &setting)?)))
    }
}

pub fn parse_sync_args(args: CliArgs<'_>) -> Result<SyncCliCommand, String> {
    let values = args.values();
    if values.is_empty() || values == ["show"] {
        return Ok(SyncCliCommand::Show);
    }
    match values[0].as_str() {
        "all" if values.len() == 1 => Ok(SyncCliCommand::Set(SyncSettingMode::All)),
        "range" => parse_range_args(&values[1..]).map(SyncCliCommand::Set),
        _ => Err(SYNC_USAGE.to_string()),
    }
}

fn parse_range_args(values: &[String]) -> Result<SyncSettingMode, String> {
    let mut start_ms = None;
    let mut end_ms = None;
    let mut idx = 0;
    while idx < values.len() {
        match values[idx].as_str() {
            "--start-ms" => {
                let value = values.get(idx + 1).ok_or_else(|| SYNC_USAGE.to_string())?;
                start_ms = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| "sync range start-ms must be a u64".to_string())?,
                );
                idx += 2;
            }
            "--end-ms" => {
                let value = values.get(idx + 1).ok_or_else(|| SYNC_USAGE.to_string())?;
                end_ms = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| "sync range end-ms must be a u64".to_string())?,
                );
                idx += 2;
            }
            _ => return Err(SYNC_USAGE.to_string()),
        }
    }
    let range = TimestampRange {
        start: start_ms.ok_or_else(|| SYNC_USAGE.to_string())?,
        end: end_ms.ok_or_else(|| SYNC_USAGE.to_string())?,
    };
    validate_mode(SyncSettingMode::Range(range))?;
    Ok(SyncSettingMode::Range(range))
}

pub fn author_setting(
    clock: &dyn CommandClock,
    mode: SyncSettingMode,
) -> Result<CommandOutput<SyncSettingReceipt>, String> {
    let effective_at_ms = clock.next_timestamp();
    let fact = setting_fact(effective_at_ms, mode)?;
    Ok(CommandOutput::new(SyncSettingReceipt {
        setting_fact_id: fact.id,
        effective_at_ms,
        mode,
    })
    .with_facts(vec![fact]))
}

pub fn setting_fact(effective_at_ms: u64, mode: SyncSettingMode) -> Result<Fact, String> {
    let setting = SyncLocalSettingFact {
        effective_at_ms,
        mode,
    };
    Ok(Fact::new(
        FactScope::Local,
        effective_at_ms,
        encode_fact(&setting)?,
    ))
}

pub fn current_setting(store: &Store) -> Result<Option<SyncSettingRow>, String> {
    let mut current = None;
    for (key, value) in store
        .table_rows(SYNC_LOCAL_SETTING_ROWS)
        .map_err(|err| format!("read sync local setting rows: {err}"))?
    {
        let row = decode_setting_row(&key, &value)?;
        if current
            .as_ref()
            .is_none_or(|active: &SyncSettingRow| setting_order(row) > setting_order(*active))
        {
            current = Some(row);
        }
    }
    Ok(current)
}

pub fn active_range(store: &Store) -> Result<TimestampRange, String> {
    Ok(match current_setting(store)?.map(|row| row.mode) {
        Some(SyncSettingMode::Range(range)) => range,
        Some(SyncSettingMode::All) | None => TimestampRange::ROOT,
    })
}

pub fn contains_timestamp(range: TimestampRange, timestamp: u64) -> bool {
    range.start <= timestamp && timestamp <= range.end
}

pub fn sync_setting_output(setting: Option<&SyncSettingRow>) -> CliOutput {
    let mode = setting.map(|row| row.mode).unwrap_or(SyncSettingMode::All);
    let fact_id = setting
        .map(|row| encode_hex_32(&row.setting_fact_id))
        .unwrap_or_else(|| "none".to_string());
    let effective_at = setting
        .map(|row| row.effective_at_ms.to_string())
        .unwrap_or_else(|| "unset".to_string());
    let range = mode_range(mode);
    CliOutput::lines(vec![
        format!("mode: {}", mode_name(mode)),
        format!("setting_fact_id: {fact_id}"),
        format!("effective_at_ms: {effective_at}"),
        format!("start_ms: {}", range.start),
        format!("end_ms: {}", range.end),
    ])
}

pub fn sync_setting_receipt_output(receipt: &SyncSettingReceipt) -> CliOutput {
    let range = mode_range(receipt.mode);
    CliOutput::lines(vec![
        format!("mode: {}", mode_name(receipt.mode)),
        format!(
            "setting_fact_id: {}",
            encode_hex_32(&receipt.setting_fact_id)
        ),
        format!("effective_at_ms: {}", receipt.effective_at_ms),
        format!("start_ms: {}", range.start),
        format!("end_ms: {}", range.end),
    ])
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<SyncLocalSettingFact, String> {
    decode_fact(bytes)
}

pub(crate) fn authenticate(
    fact: &Fact,
    setting: SyncLocalSettingFact,
    _context: &ProjectionContext,
) -> Result<SyncLocalSettingFact, String> {
    verify_fact_id(fact)?;
    if fact.scope != FactScope::Local {
        return Err("sync local setting fact must have local scope".to_string());
    }
    validate_mode(setting.mode)?;
    Ok(setting)
}

fn encode_fact(setting: &SyncLocalSettingFact) -> Result<Vec<u8>, String> {
    validate_mode(setting.mode)?;
    let range = mode_range(setting.mode);
    let mut out = Vec::with_capacity(FACT_BYTES);
    out.push(TYPE_SYNC_LOCAL_SETTING);
    out.push(mode_byte(setting.mode));
    out.extend_from_slice(&setting.effective_at_ms.to_be_bytes());
    out.extend_from_slice(&range.start.to_be_bytes());
    out.extend_from_slice(&range.end.to_be_bytes());
    Ok(out)
}

fn decode_fact(bytes: &[u8]) -> Result<SyncLocalSettingFact, String> {
    if bytes.len() != FACT_BYTES {
        return Err("sync local setting fact has invalid length".to_string());
    }
    if bytes[0] != TYPE_SYNC_LOCAL_SETTING {
        return Err("expected sync local setting fact".to_string());
    }
    let effective_at_ms = u64::from_be_bytes(bytes[2..10].try_into().unwrap());
    let start = u64::from_be_bytes(bytes[10..18].try_into().unwrap());
    let end = u64::from_be_bytes(bytes[18..26].try_into().unwrap());
    let mode = match bytes[1] {
        MODE_ALL => {
            if start != TimestampRange::ROOT.start || end != TimestampRange::ROOT.end {
                return Err("sync all setting must encode the root range".to_string());
            }
            SyncSettingMode::All
        }
        MODE_RANGE => SyncSettingMode::Range(TimestampRange { start, end }),
        _ => return Err("sync local setting mode is invalid".to_string()),
    };
    validate_mode(mode)?;
    Ok(SyncLocalSettingFact {
        effective_at_ms,
        mode,
    })
}

fn setting_row(
    setting_fact_id: FactId,
    setting: &SyncLocalSettingFact,
) -> Result<TableRow, String> {
    let range = mode_range(setting.mode);
    SYNC_LOCAL_SETTING_ROW_SCHEMA.row(
        &[RowValue::Bytes(setting_fact_id.to_vec())],
        &[
            RowValue::U8(mode_byte(setting.mode)),
            RowValue::U64(setting.effective_at_ms),
            RowValue::U64(range.start),
            RowValue::U64(range.end),
        ],
    )
}

fn decode_setting_row(key: &[u8], value: &[u8]) -> Result<SyncSettingRow, String> {
    let key_fields = SYNC_LOCAL_SETTING_ROW_SCHEMA.decode_key(key)?;
    let value_fields = SYNC_LOCAL_SETTING_ROW_SCHEMA.decode_value(value)?;
    let mode = match value_fields[0].as_u8("mode")? {
        MODE_ALL => SyncSettingMode::All,
        MODE_RANGE => SyncSettingMode::Range(TimestampRange {
            start: value_fields[2].as_u64("start_ms")?,
            end: value_fields[3].as_u64("end_ms")?,
        }),
        _ => return Err("sync local setting row mode is invalid".to_string()),
    };
    validate_mode(mode)?;
    Ok(SyncSettingRow {
        setting_fact_id: key_fields[0].as_bytes32("setting_fact_id")?,
        effective_at_ms: value_fields[1].as_u64("effective_at_ms")?,
        mode,
    })
}

fn setting_order(row: SyncSettingRow) -> (u64, FactId) {
    (row.effective_at_ms, row.setting_fact_id)
}

fn validate_mode(mode: SyncSettingMode) -> Result<(), String> {
    if let SyncSettingMode::Range(range) = mode {
        if range.start > range.end {
            return Err("sync range start-ms must be <= end-ms".to_string());
        }
    }
    Ok(())
}

fn mode_byte(mode: SyncSettingMode) -> u8 {
    match mode {
        SyncSettingMode::All => MODE_ALL,
        SyncSettingMode::Range(_) => MODE_RANGE,
    }
}

fn mode_range(mode: SyncSettingMode) -> TimestampRange {
    match mode {
        SyncSettingMode::All => TimestampRange::ROOT,
        SyncSettingMode::Range(range) => range,
    }
}

fn mode_name(mode: SyncSettingMode) -> &'static str {
    match mode {
        SyncSettingMode::All => "all",
        SyncSettingMode::Range(_) => "range",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::command::FnClock;
    use crate::core::schema::CORE_SCHEMA_SOURCE;
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;

    #[test]
    fn setting_fact_round_trips_fixed_width() {
        let mode = SyncSettingMode::Range(TimestampRange { start: 10, end: 20 });
        let fact = setting_fact(123, mode).expect("setting fact");

        assert_eq!(fact.scope, FactScope::Local);
        assert_eq!(fact.bytes.len(), FACT_BYTES);
        assert_eq!(
            decode_fact(&fact.bytes).expect("decode setting"),
            SyncLocalSettingFact {
                effective_at_ms: 123,
                mode,
            }
        );
    }

    #[test]
    fn current_setting_uses_most_recent_row_then_fact_id() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("store");
        let older = setting_fact(
            100,
            SyncSettingMode::Range(TimestampRange { start: 1, end: 2 }),
        )
        .expect("older");
        let newer = setting_fact(200, SyncSettingMode::All).expect("newer");
        SyncLocalSettingProjector::new()
            .project(&older, &ProjectionContext::default())
            .expect("project older")
            .effects
            .row_mutations
            .into_iter()
            .for_each(|mutation| {
                if let RowMutation::PutRow(row) = mutation {
                    store.insert_table_rows(vec![row]).expect("insert older");
                }
            });
        SyncLocalSettingProjector::new()
            .project(&newer, &ProjectionContext::default())
            .expect("project newer")
            .effects
            .row_mutations
            .into_iter()
            .for_each(|mutation| {
                if let RowMutation::PutRow(row) = mutation {
                    store.insert_table_rows(vec![row]).expect("insert newer");
                }
            });

        assert_eq!(
            current_setting(&store)
                .expect("current")
                .unwrap()
                .setting_fact_id,
            newer.id
        );
        assert_eq!(active_range(&store).expect("active"), TimestampRange::ROOT);
    }

    #[test]
    fn author_setting_emits_one_local_fact() {
        let output = author_setting(
            &FnClock(|| 55),
            SyncSettingMode::Range(TimestampRange { start: 40, end: 50 }),
        )
        .expect("author");

        assert_eq!(output.facts.len(), 1);
        assert_eq!(output.facts[0].scope, FactScope::Local);
        assert_eq!(output.receipt.effective_at_ms, 55);
    }
}
