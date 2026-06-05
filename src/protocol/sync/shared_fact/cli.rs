//! CLI parsing and rendering for sync shared-fact status.
//!
//! Sync status reports the local shareable index root.
//!
//! This file owns only argument shape and text formatting. The index and
//! fingerprint rules stay in `rows`, and actual connection sends stay in the
//! connection send modules.

use crate::core::cli::{decode_hex_32_named, encode_hex, CliArgs, CliOutput};
use crate::core::facts::FactId;

use super::index::SyncStatus;

pub const SYNC_STATUS_USAGE: &str = "sync-status";
pub const SYNC_RANGE_USAGE: &str = "sync-range PEER_OR_CONNECTION_ID_HEX --workspace WORKSPACE_ID_HEX --start-ms START --end-ms END (--with-deps|--without-deps)";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncRangeArgs {
    pub peer_or_connection_id: FactId,
    pub workspace_id: FactId,
    pub start_ms: u64,
    pub end_ms: u64,
    pub include_deps: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncRangeDispatched {
    pub connection_id: FactId,
    pub workspace_id: FactId,
    pub start_ms: u64,
    pub end_ms: u64,
    pub include_deps: bool,
    pub queued: bool,
}

pub fn require_sync_status_args(args: CliArgs<'_>) -> Result<(), String> {
    args.require_len(0, SYNC_STATUS_USAGE)
}

pub fn parse_sync_range_args(args: CliArgs<'_>) -> Result<SyncRangeArgs, String> {
    let values = args.values();
    if values.len() != 8 {
        return Err(SYNC_RANGE_USAGE.to_string());
    }
    let peer_or_connection_id = decode_hex_32_named(&values[0], "peer or connection id")?;
    let mut workspace_id = None;
    let mut start_ms = None;
    let mut end_ms = None;
    let mut include_deps = None;
    let mut index = 1;
    while index < values.len() {
        match values[index].as_str() {
            "--workspace" => {
                index += 1;
                let value = values
                    .get(index)
                    .ok_or_else(|| SYNC_RANGE_USAGE.to_string())?;
                workspace_id = Some(decode_hex_32_named(value, "workspace id")?);
            }
            "--start-ms" => {
                index += 1;
                let value = values
                    .get(index)
                    .ok_or_else(|| SYNC_RANGE_USAGE.to_string())?;
                start_ms = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| SYNC_RANGE_USAGE.to_string())?,
                );
            }
            "--end-ms" => {
                index += 1;
                let value = values
                    .get(index)
                    .ok_or_else(|| SYNC_RANGE_USAGE.to_string())?;
                end_ms = Some(
                    value
                        .parse::<u64>()
                        .map_err(|_| SYNC_RANGE_USAGE.to_string())?,
                );
            }
            "--with-deps" => {
                include_deps = Some(true);
            }
            "--without-deps" => {
                include_deps = Some(false);
            }
            _ => return Err(SYNC_RANGE_USAGE.to_string()),
        }
        index += 1;
    }
    let workspace_id = workspace_id.ok_or_else(|| SYNC_RANGE_USAGE.to_string())?;
    let start_ms = start_ms.ok_or_else(|| SYNC_RANGE_USAGE.to_string())?;
    let end_ms = end_ms.ok_or_else(|| SYNC_RANGE_USAGE.to_string())?;
    let include_deps = include_deps.ok_or_else(|| SYNC_RANGE_USAGE.to_string())?;
    if start_ms > end_ms {
        return Err("sync-range start-ms must be <= end-ms".to_string());
    }
    Ok(SyncRangeArgs {
        peer_or_connection_id,
        workspace_id,
        start_ms,
        end_ms,
        include_deps,
    })
}

pub fn sync_status_output(status: &SyncStatus) -> CliOutput {
    CliOutput::lines(vec![
        format!("indexed_facts: {}", status.indexed_facts),
        format!("root_count: {}", status.root_count),
        format!("root_fingerprint: {}", encode_hex(&status.root_fingerprint)),
        format!("pending_purges: {}", status.pending_purges),
    ])
}

pub fn sync_range_output(output: SyncRangeDispatched) -> CliOutput {
    CliOutput::lines(vec![
        format!("connection_id: {}", encode_hex(&output.connection_id)),
        format!("workspace_id: {}", encode_hex(&output.workspace_id)),
        format!("start_ms: {}", output.start_ms),
        format!("end_ms: {}", output.end_ms),
        format!(
            "deps: {}",
            if output.include_deps {
                "with"
            } else {
                "without"
            }
        ),
        format!("queued: {}", if output.queued { "yes" } else { "no" }),
    ])
}
