//! CLI formatting for local protocol update facts.

use crate::core::cli::{encode_hex_32, CliOutput};

use super::api::UpdateReceipt;

pub fn update_output(receipt: &UpdateReceipt, pending_projection: usize) -> CliOutput {
    CliOutput::lines(vec![
        format!("update_fact: {}", encode_hex_32(&receipt.update_fact_id)),
        format!("protocol_version: {}", receipt.protocol_version),
        format!("applied_at_ms: {}", receipt.applied_at_ms),
        format!("pending_projection: {pending_projection}"),
    ])
}
