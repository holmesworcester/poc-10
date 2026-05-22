//! CLI parsing and rendering for disappearing-message retention settings.
//!
//! Disappearing-message commands expose retention as workspace policy: set a
//! TTL, tighten it with confirmation, compact old tombstones, or inspect the
//! current floor. This file owns argument shape and report text only. Policy
//! evaluation and row changes stay in the command, query, and retention modules.

use crate::core::cli::{decode_hex_32_named, encode_hex_32, CliArgs, CliOutput};

use super::commands::StatusReport;

pub const DISAPPEARING_SET_USAGE: &str =
    "disappearing-set WORKSPACE_ID_HEX TTL_MINUTES [--floor MINUTE]";
pub const DISAPPEARING_STATUS_USAGE: &str = "disappearing-status WORKSPACE_ID_HEX";
pub const DISAPPEARING_TIGHTEN_USAGE: &str =
    "disappearing-tighten WORKSPACE_ID_HEX TTL_MINUTES [--yes|-y]";
pub const DISAPPEARING_COMPACT_USAGE: &str = "disappearing-compact WORKSPACE_ID_HEX";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisappearingSetArgs {
    pub workspace_id: [u8; 32],
    pub ttl_minutes: u32,
    pub explicit_floor: Option<u64>,
}

pub fn parse_disappearing_set_args(values: &[String]) -> Result<DisappearingSetArgs, String> {
    if values.len() < 2 {
        return Err(DISAPPEARING_SET_USAGE.to_string());
    }
    let workspace_id = decode_hex_32_named(&values[0], "workspace id")?;
    let ttl_minutes = values[1]
        .parse::<u32>()
        .map_err(|_| "disappearing-set ttl must be a u32".to_string())?;
    let mut explicit_floor = None;
    let mut idx = 2;
    while idx < values.len() {
        match values[idx].as_str() {
            "--floor" => {
                let value = values
                    .get(idx + 1)
                    .ok_or_else(|| "disappearing-set --floor requires a value".to_string())?;
                explicit_floor = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| "disappearing-set floor must be a u64".to_string())?,
                );
                idx += 2;
            }
            arg if arg.starts_with("--floor=") => {
                let value = arg.trim_start_matches("--floor=");
                explicit_floor = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| "disappearing-set floor must be a u64".to_string())?,
                );
                idx += 1;
            }
            _ => return Err(DISAPPEARING_SET_USAGE.to_string()),
        }
    }
    Ok(DisappearingSetArgs {
        workspace_id,
        ttl_minutes,
        explicit_floor,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisappearingTightenArgs {
    pub workspace_id: [u8; 32],
    pub ttl_minutes: u32,
    pub yes: bool,
}

pub fn parse_disappearing_tighten_args(
    values: &[String],
) -> Result<DisappearingTightenArgs, String> {
    if values.len() < 2 {
        return Err(DISAPPEARING_TIGHTEN_USAGE.to_string());
    }
    let workspace_id = decode_hex_32_named(&values[0], "workspace id")?;
    let ttl_minutes = values[1]
        .parse::<u32>()
        .map_err(|_| "disappearing-tighten ttl must be a u32".to_string())?;
    let mut yes = false;
    for value in &values[2..] {
        match value.as_str() {
            "--yes" | "-y" => yes = true,
            _ => return Err(DISAPPEARING_TIGHTEN_USAGE.to_string()),
        }
    }
    Ok(DisappearingTightenArgs {
        workspace_id,
        ttl_minutes,
        yes,
    })
}

pub fn status_workspace_id(args: CliArgs<'_>) -> Result<[u8; 32], String> {
    args.require_len(1, DISAPPEARING_STATUS_USAGE)?;
    decode_hex_32_named(args.get(0).expect("length checked"), "workspace id")
}

pub fn compact_workspace_id(args: CliArgs<'_>) -> Result<[u8; 32], String> {
    args.require_len(1, DISAPPEARING_COMPACT_USAGE)?;
    decode_hex_32_named(args.get(0).expect("length checked"), "workspace id")
}

pub fn status_output(report: &StatusReport) -> CliOutput {
    let setting_fact_id = report
        .setting_fact_id
        .as_ref()
        .map(encode_hex_32)
        .unwrap_or_else(|| "none".to_string());
    let ttl = report
        .ttl_minutes
        .map(|ttl| ttl.to_string())
        .unwrap_or_else(|| "unset".to_string());
    let now_minute = report
        .now_minute
        .map(|minute| minute.to_string())
        .unwrap_or_else(|| "unset".to_string());
    let last_chopped_floor = report
        .last_chopped_floor
        .map(|minute| minute.to_string())
        .unwrap_or_else(|| "none".to_string());

    CliOutput::lines(vec![
        format!("workspace: {}", encode_hex_32(&report.workspace_id)),
        format!("setting_fact_id: {setting_fact_id}"),
        format!("current_ttl_minutes: {ttl}"),
        format!("current_floor_minute: {}", report.setting_floor_minute),
        format!("last_chopped_floor: {last_chopped_floor}"),
        format!("now_minute: {now_minute}"),
        format!("horizon_floor: {}", report.horizon_floor),
        format!("effective_floor: {}", report.effective_floor),
        format!("live_messages: {}", report.live_messages),
        format!("message_tombstones: {}", report.message_tombstones),
        "leaf_tombstones: 0".to_string(),
        "pending_purges: 0".to_string(),
    ])
}
