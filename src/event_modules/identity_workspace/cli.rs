//! CLI adapter for workspace commands.
//!
//! This file owns only frontend concerns: argv parsing and text formatting.
//! It calls `commands.rs` for the actual workspace workflow and never opens a
//! store, drains projection, or dispatches handlers.

use crate::core::cli::{CliArgs, CliOutput};
use crate::core::command_context::{CommandContext, CommandOutput};
use crate::event_modules::identity_workspace::{commands, queries};

pub const CREATE_WORKSPACE_USAGE: &str =
    "create-workspace (--public-key HEX64 --name NAME | NAME --username USER --devicename DEVICE)";
pub const WORKSPACES_USAGE: &str = "workspaces";
pub const COUNT_USAGE: &str = "count";

pub fn create_workspace(
    ctx: &CommandContext<'_>,
    args: CliArgs<'_>,
) -> Result<CommandOutput<commands::CreateWorkspaceReceipt>, String> {
    let parsed = CreateWorkspaceArgs::parse(args)?;
    match parsed.identity {
        Some(identity) => commands::create_workspace_with_identity(ctx, &parsed.name, identity),
        None => commands::create_workspace(
            ctx,
            parsed
                .public_key
                .ok_or_else(|| "create-workspace requires --public-key HEX64".to_string())?,
            &parsed.name,
        ),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CreateWorkspaceArgs<'a> {
    name: String,
    public_key: Option<[u8; 32]>,
    identity: Option<commands::BootstrapIdentity<'a>>,
}

impl<'a> CreateWorkspaceArgs<'a> {
    fn parse(args: CliArgs<'a>) -> Result<Self, String> {
        let mut public_key = None;
        let mut name = None;
        let mut username = None;
        let mut device_name = None;
        let mut _ttl_minutes = None;
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
                    name = Some(rest.next().ok_or_else(|| {
                        "create-workspace requires a value after --name".to_string()
                    })?);
                }
                "--username" => {
                    username = Some(rest.next().ok_or_else(|| {
                        "create-workspace requires a value after --username".to_string()
                    })?);
                }
                "--devicename" | "--device-name" => {
                    device_name = Some(rest.next().ok_or_else(|| {
                        "create-workspace requires a value after --devicename".to_string()
                    })?);
                }
                "--ttl-minutes" => {
                    let value = rest.next().ok_or_else(|| {
                        "create-workspace requires a value after --ttl-minutes".to_string()
                    })?;
                    let parsed = value.parse::<u32>().map_err(|_| {
                        "create-workspace --ttl-minutes must be a positive integer".to_string()
                    })?;
                    if parsed == 0 {
                        return Err(
                            "create-workspace --ttl-minutes must be a positive integer".to_string()
                        );
                    }
                    _ttl_minutes = Some(parsed);
                }
                other if !other.starts_with('-') && name.is_none() => {
                    name = Some(arg);
                }
                other => return Err(format!("unknown create-workspace argument `{other}`")),
            }
        }
        let name = name
            .ok_or_else(|| "create-workspace requires --name NAME or positional NAME".to_string())?
            .to_string();

        let identity = match (username, device_name) {
            (Some(username), Some(device_name)) => Some(commands::BootstrapIdentity {
                username,
                device_name,
                ttl_minutes: _ttl_minutes,
            }),
            (None, None) => None,
            (None, Some(_)) => {
                return Err("create-workspace --devicename requires --username".to_string())
            }
            (Some(_), None) => {
                return Err("create-workspace --username requires --devicename".to_string())
            }
        };
        if identity.is_some() && public_key.is_some() {
            return Err(
                "create-workspace legacy identity form derives its own public key".to_string(),
            );
        }
        Ok(Self {
            name,
            public_key,
            identity,
        })
    }
}

pub fn created_workspace_output(
    workspace: &queries::WorkspaceSummary,
    bootstrap_user_id: Option<[u8; 32]>,
) -> CliOutput {
    let mut lines = vec![
        format!("workspace_id: {}", encode_hex(&workspace.workspace_id)),
        format!("created_at_ms: {}", workspace.created_at_ms),
        format!("name: {}", workspace.name),
    ];
    if let Some(user_id) = bootstrap_user_id {
        lines.push(format!("user_id: {}", encode_hex(&user_id)));
    }
    CliOutput::lines(lines)
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

pub fn count_output(
    workspace_rows: usize,
    events: usize,
    sync_events: usize,
    applied_events: usize,
    connections: usize,
    connection_events: usize,
    invite_accepted: usize,
) -> CliOutput {
    CliOutput::lines(vec![
        format!("workspace_rows: {workspace_rows}"),
        format!("events: {events}"),
        format!("sync_events: {sync_events}"),
        format!("applied_events: {applied_events}"),
        format!("connections: {connections}"),
        format!("connection_events: {connection_events}"),
        format!("invite_accepted: {invite_accepted}"),
    ])
}

pub fn count_report_output(report: &super::runtime_counts::RuntimeCountReport) -> CliOutput {
    count_output(
        report.workspace_rows,
        report.events,
        report.sync_events,
        report.applied_events,
        report.connections,
        report.connection_events,
        report.invite_accepted,
    )
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
