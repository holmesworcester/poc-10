//! CLI adapter for workspace commands.
//!
//! This file owns only frontend concerns: argv parsing and text formatting.
//! It calls `api.rs` for the actual workspace workflow and never opens a
//! store, drains projection, or dispatches handlers.

use crate::core::cli::{decode_hex_32_named as decode_hex_32, encode_hex, CliArgs, CliOutput};
use crate::core::command::{AuthoredFacts, CommandClock};
use crate::core::db::Db;
use crate::protocol::auth::workspace::{api, queries};

pub const CREATE_WORKSPACE_USAGE: &str =
    "create-workspace (--public-key HEX64 --name NAME | NAME --username USER --devicename DEVICE)";
pub const WORKSPACES_USAGE: &str = "workspaces";
pub const COUNT_USAGE: &str = "count";

pub fn create_workspace(
    store: &Db,
    clock: &dyn CommandClock,
    args: CliArgs<'_>,
) -> Result<AuthoredFacts<api::CreateWorkspaceReceipt>, String> {
    let parsed = CreateWorkspaceArgs::parse(args)?;
    match parsed.identity {
        Some(identity) => api::create_workspace_with_identity(store, clock, &parsed.name, identity),
        None => api::create_workspace(
            clock,
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
    identity: Option<api::BootstrapIdentity<'a>>,
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
                        "create-workspace --ttl-minutes must be a non-negative integer".to_string()
                    })?;
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
            (Some(username), Some(device_name)) => Some(api::BootstrapIdentity {
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
                "create-workspace bootstrap identity form derives its own public key".to_string(),
            );
        }
        Ok(Self {
            name,
            public_key,
            identity,
        })
    }
}

pub fn created_workspace_output(receipt: &api::CreateWorkspaceReceipt) -> CliOutput {
    let mut lines = vec![
        format!("workspace_id: {}", encode_hex(&receipt.workspace_fact_id)),
        format!("created_at_ms: {}", receipt.created_at_ms),
        format!("name: {}", receipt.name),
    ];
    if let Some(user_id) = receipt.user_id {
        lines.push(format!("user_id: {}", encode_hex(&user_id)));
    }
    CliOutput::lines(lines)
}

pub fn workspaces(store: &Db, args: CliArgs<'_>) -> Result<Vec<queries::WorkspaceSummary>, String> {
    args.require_len(0, WORKSPACES_USAGE)?;
    queries::list_workspaces(store)
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

pub fn count(store: &Db, args: CliArgs<'_>) -> Result<usize, String> {
    args.require_len(0, COUNT_USAGE)?;
    queries::count_workspaces(store)
}

pub fn count_output(
    workspace_rows: usize,
    facts: usize,
    sync_facts: usize,
    applied_facts: usize,
    pending_intents: usize,
    connections: usize,
    connection_facts: usize,
    invite_accepted: usize,
) -> CliOutput {
    CliOutput::lines(vec![
        format!("workspace_rows: {workspace_rows}"),
        format!("facts: {facts}"),
        format!("sync_facts: {sync_facts}"),
        format!("applied_facts: {applied_facts}"),
        format!("pending_intents: {pending_intents}"),
        format!("connections: {connections}"),
        format!("connection_facts: {connection_facts}"),
        format!("invite_accepted: {invite_accepted}"),
    ])
}

pub fn count_report_output(report: &super::queries::RuntimeCountReport) -> CliOutput {
    count_output(
        report.workspace_rows,
        report.facts,
        report.sync_facts,
        report.applied_facts,
        report.pending_intents,
        report.connections,
        report.connection_facts,
        report.invite_accepted,
    )
}
