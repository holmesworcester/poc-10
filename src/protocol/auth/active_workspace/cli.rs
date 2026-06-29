//! CLI adapter for the `use-workspace` command.
//!
//! Owns argv parsing and output formatting for selecting the active workspace.
//! Fact construction lives in `author.rs`; admission stays at the command host.

use crate::core::cli::{decode_hex_32, encode_hex_32, CliArgs, CliOutput};
use crate::core::facts::FactId;

use super::author::ActiveWorkspaceReceipt;

pub const USE_WORKSPACE_USAGE: &str = "use-workspace (N | WORKSPACE_ID_HEX)";

/// How the user named the workspace to make active: either its 1-based position
/// in the `workspaces`/`status` numbered list, or its full hex id. The position
/// is resolved against projected rows at the command boundary, so parsing only
/// classifies the argument here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UseWorkspaceSelector {
    Position(usize),
    Id(FactId),
}

pub fn parse_use_workspace_args(args: CliArgs<'_>) -> Result<UseWorkspaceSelector, String> {
    args.require_len(1, USE_WORKSPACE_USAGE)?;
    let value = args.get(0).expect("length checked");
    // A bare integer selects by list position; a 64-char hex id is never a small
    // integer, so this classification is unambiguous.
    if let Ok(position) = value.parse::<usize>() {
        if position == 0 {
            return Err("use-workspace position is 1-based".to_string());
        }
        return Ok(UseWorkspaceSelector::Position(position));
    }
    Ok(UseWorkspaceSelector::Id(decode_hex_32(value)?))
}

pub fn use_workspace_output(receipt: &ActiveWorkspaceReceipt) -> CliOutput {
    CliOutput::lines(vec![
        format!("active_workspace: {}", encode_hex_32(&receipt.workspace_id)),
        format!(
            "selection_fact_id: {}",
            encode_hex_32(&receipt.setting_fact_id)
        ),
        format!("effective_at_ms: {}", receipt.effective_at_ms),
    ])
}
