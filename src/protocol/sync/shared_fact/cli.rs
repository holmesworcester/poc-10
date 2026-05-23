//! CLI parsing and rendering for sync shared-fact status.
//!
//! Sync status commands report the local shareable index and expose a
//! compatibility drain command. This file owns only argument shape and text
//! formatting. The index and fingerprint rules stay in `rows`, and actual
//! connection sends stay in connection intents.

use crate::core::cli::{encode_hex, CliArgs, CliOutput};

use super::rows::SyncStatus;

pub const SYNC_STATUS_USAGE: &str = "sync-status";
pub const NEGENTROPY_DRAIN_USAGE: &str = "negentropy-drain [LIMIT]";

pub fn parse_negentropy_drain_limit(args: CliArgs<'_>) -> Result<Option<usize>, String> {
    if args.values().len() > 1 {
        return Err(NEGENTROPY_DRAIN_USAGE.to_string());
    }
    args.get(0)
        .map(|value| {
            value
                .parse::<usize>()
                .map_err(|_| NEGENTROPY_DRAIN_USAGE.to_string())
        })
        .transpose()
}

pub fn require_sync_status_args(args: CliArgs<'_>) -> Result<(), String> {
    args.require_len(0, SYNC_STATUS_USAGE)
}

pub fn sync_status_output(status: &SyncStatus) -> CliOutput {
    CliOutput::lines(vec![
        format!("indexed_facts: {}", status.indexed_facts),
        format!("root_count: {}", status.root_count),
        format!("root_fingerprint: {}", encode_hex(&status.root_fingerprint)),
        format!("pending_purges: {}", status.pending_purges),
    ])
}

pub fn negentropy_drain_output(status: &SyncStatus) -> CliOutput {
    CliOutput::lines(vec![
        "drained: 0".to_string(),
        "removed_from_index: 0".to_string(),
        format!("remaining_pending: {}", status.pending_purges),
        format!("new_root_count: {}", status.root_count),
        format!(
            "new_root_fingerprint: {}",
            encode_hex(&status.root_fingerprint)
        ),
    ])
}
