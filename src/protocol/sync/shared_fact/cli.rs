//! CLI parsing and rendering for sync shared-fact status.
//!
//! Sync status reports the local shareable index root.
//!
//! This file owns only argument shape and text formatting. The index and
//! fingerprint rules stay in `rows`, and actual connection sends stay in the
//! connection send modules.

use crate::core::cli::{encode_hex, CliArgs, CliOutput};

use super::index::SyncStatus;

pub const SYNC_STATUS_USAGE: &str = "sync-status";

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
