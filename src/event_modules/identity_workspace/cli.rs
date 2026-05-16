//! CLI adapter for workspace commands.
//!
//! This file owns only frontend concerns: argv parsing and text formatting.
//! It calls `commands.rs` for the actual workspace workflow and never opens a
//! store, drains projection, or dispatches handlers.

use crate::core::cli::{CliArgs, CliOutput};
use crate::core::command_context::{CommandContext, CommandOutput};
use crate::event_modules::identity_workspace::{commands, queries};

pub const CREATE_WORKSPACE_USAGE: &str = "create-workspace --public-key HEX64 --name NAME";
pub const WORKSPACES_USAGE: &str = "workspaces";
pub const COUNT_USAGE: &str = "count";

pub fn create_workspace(
    ctx: &CommandContext<'_>,
    args: CliArgs<'_>,
) -> Result<CommandOutput<commands::CreateWorkspaceReceipt>, String> {
    let mut public_key = None;
    let mut name = None;
    let mut rest = args.values().iter();
    while let Some(arg) = rest.next() {
        match arg.as_str() {
            "--public-key" => {
                let value = rest.next().ok_or_else(|| {
                    "create-workspace requires a HEX64 value after --public-key".to_string()
                })?;
                public_key = Some(decode_hex_32(value, "public key")?);
            }
            "--name" => {
                name =
                    Some(rest.next().ok_or_else(|| {
                        "create-workspace requires a value after --name".to_string()
                    })?);
            }
            other => return Err(format!("unknown create-workspace argument `{other}`")),
        }
    }
    let public_key =
        public_key.ok_or_else(|| "create-workspace requires --public-key HEX64".to_string())?;
    let name = name.ok_or_else(|| "create-workspace requires --name NAME".to_string())?;

    commands::create_workspace(ctx, public_key, name)
}

pub fn created_workspace_output(workspace: &queries::WorkspaceSummary) -> CliOutput {
    CliOutput::lines(vec![
        format!("workspace_id: {}", encode_hex(&workspace.workspace_id)),
        format!("created_at_ms: {}", workspace.created_at_ms),
        format!("name: {}", workspace.name),
    ])
}

pub fn workspaces(
    ctx: &CommandContext<'_>,
    args: CliArgs<'_>,
) -> Result<Vec<queries::WorkspaceSummary>, String> {
    args.require_len(0, WORKSPACES_USAGE)?;
    queries::list_workspaces(ctx.store())
}

pub fn workspaces_output(workspaces: &[queries::WorkspaceSummary]) -> CliOutput {
    if workspaces.is_empty() {
        return CliOutput::line("workspaces: 0");
    }

    let mut lines = vec![format!("workspaces: {}", workspaces.len())];
    for workspace in workspaces {
        lines.push(format!(
            "{} created_at_ms={} public_key={} name={}",
            encode_hex(&workspace.workspace_id),
            workspace.created_at_ms,
            encode_hex(&workspace.public_key),
            workspace.name
        ));
    }
    CliOutput::lines(lines)
}

pub fn count(ctx: &CommandContext<'_>, args: CliArgs<'_>) -> Result<usize, String> {
    args.require_len(0, COUNT_USAGE)?;
    queries::count_workspaces(ctx.store())
}

pub fn count_output(workspace_rows: usize) -> CliOutput {
    CliOutput::line(format!("workspace_rows: {workspace_rows}"))
}

fn decode_hex_32(value: &str, label: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err(format!("{label} must be 64 hex characters"));
    }
    let mut out = [0; 32];
    let bytes = value.as_bytes();
    for index in 0..32 {
        out[index] =
            (hex_nibble(bytes[index * 2], label)? << 4) | hex_nibble(bytes[index * 2 + 1], label)?;
    }
    Ok(out)
}

fn hex_nibble(byte: u8, label: &str) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("{label} contains a non-hex character")),
    }
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}
