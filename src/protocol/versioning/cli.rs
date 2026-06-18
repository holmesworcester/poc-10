//! CLI formatting for protocol versioning commands.

use crate::core::cli::{encode_hex_32, CliOutput};

use super::api::UpdateReceipt;
use super::queries::StateSummary;

pub const UPDATE_USAGE: &str = "update";
pub const STATE_SUMMARY_USAGE: &str = "state-summary";

pub fn update_output(receipt: &UpdateReceipt, pending_projection: usize) -> CliOutput {
    CliOutput::lines(vec![
        format!("update_fact: {}", encode_hex_32(&receipt.update_fact_id)),
        format!("protocol_version: {}", receipt.protocol_version),
        format!("applied_at_ms: {}", receipt.applied_at_ms),
        format!("pending_projection: {pending_projection}"),
    ])
}

pub fn state_summary_output(summary: &StateSummary) -> CliOutput {
    let mut lines = vec![
        format!("state_hash: {}", encode_hex_32(&summary.state_hash)),
        format!("areas: {}", summary.areas.len()),
    ];
    for area in &summary.areas {
        lines.push(format!(
            "area_{}: {} {}",
            area.area,
            area.count,
            encode_hex_32(&area.hash)
        ));
    }
    CliOutput::lines(lines)
}
