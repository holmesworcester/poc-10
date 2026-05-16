//! Product-facing `match` binary entrypoint.
//!
//! `main.rs` stays intentionally tiny: it collects argv and delegates here.
//! This module chooses the current Topo protocol implementation behind the
//! product-facing `match` binary name. It should not grow protocol logic,
//! projection code, handler dispatch, or fact construction.

use crate::core::cli::CliArgs;
use crate::core::command_context::{
    CommandClock, IdentityVault, LocalEncryptionCapability, LocalSigningCapability, WorkspaceId,
};
use crate::event_modules::identity_workspace;
use crate::protocol::runtime::ProtocolRuntime;
use std::path::PathBuf;

pub fn run(argv: Vec<String>) -> Result<(), String> {
    let parsed = ParsedArgs::parse(argv)?;
    match parsed.command.first().map(String::as_str) {
        None => Err(top_level_usage("missing command")),
        Some("-h" | "--help" | "help") => {
            println!("{}", top_level_usage("Topo match CLI"));
            Ok(())
        }
        Some("create-workspace") => run_create_workspace(parsed),
        Some("workspaces") => run_workspaces(parsed),
        Some("count") => run_count(parsed),
        Some(command) => Err(top_level_usage(&format!(
            "command `{command}` is not ported to the target runtime yet"
        ))),
    }
}

fn top_level_usage(reason: &str) -> String {
    format!(
        "{reason}\nusage:\n  match --db PATH {create_workspace_usage}\n\
         match --db PATH {workspaces_usage}\n\
         match --db PATH {count_usage}\n\n\
         available commands run through the target core runtime facade",
        create_workspace_usage = identity_workspace::cli::CREATE_WORKSPACE_USAGE,
        workspaces_usage = identity_workspace::cli::WORKSPACES_USAGE,
        count_usage = identity_workspace::cli::COUNT_USAGE
    )
}

fn run_create_workspace(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("create-workspace requires --db PATH"))?;
    let mut runtime = ProtocolRuntime::open_disk(db)?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        identity_workspace::cli::create_workspace(&ctx, CliArgs::new(&parsed.command[1..]))?
    };
    let receipt = runtime.submit_command_output(output)?;
    runtime.drain_projection_until_idle(8, 64)?;
    let workspace =
        identity_workspace::queries::workspace_by_id(runtime.store(), receipt.workspace_fact_id)?;
    runtime.save()?;

    for line in identity_workspace::cli::created_workspace_output(&workspace).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_workspaces(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("workspaces requires --db PATH"))?;
    let runtime = ProtocolRuntime::open_disk(db)?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        identity_workspace::cli::workspaces(&ctx, CliArgs::new(&parsed.command[1..]))?
    };

    for line in identity_workspace::cli::workspaces_output(&output).lines {
        println!("{line}");
    }
    Ok(())
}

fn run_count(parsed: ParsedArgs) -> Result<(), String> {
    let db = parsed
        .db
        .ok_or_else(|| top_level_usage("count requires --db PATH"))?;
    let runtime = ProtocolRuntime::open_disk(db)?;
    let clock = SystemClock;
    let vault = EmptyVault;
    let output = {
        let ctx = runtime.command_context(&clock, &vault);
        identity_workspace::cli::count(&ctx, CliArgs::new(&parsed.command[1..]))?
    };

    for line in identity_workspace::cli::count_output(output).lines {
        println!("{line}");
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedArgs {
    db: Option<PathBuf>,
    command: Vec<String>,
}

impl ParsedArgs {
    fn parse(argv: Vec<String>) -> Result<Self, String> {
        let mut db = None;
        let mut command = Vec::new();
        let mut iter = argv.into_iter();
        while let Some(arg) = iter.next() {
            if !command.is_empty() {
                command.push(arg);
                command.extend(iter);
                break;
            }
            match arg.as_str() {
                "--db" => {
                    let value = iter
                        .next()
                        .ok_or_else(|| "--db requires a path".to_string())?;
                    if db.replace(PathBuf::from(value)).is_some() {
                        return Err("--db may be supplied only once".to_string());
                    }
                }
                _ => command.push(arg),
            }
        }
        Ok(Self { db, command })
    }
}

struct SystemClock;

impl CommandClock for SystemClock {
    fn next_timestamp(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or(0)
    }
}

struct EmptyVault;

impl IdentityVault for EmptyVault {
    fn local_signing_capability(
        &self,
        _workspace_id: WorkspaceId,
    ) -> Result<LocalSigningCapability, String> {
        Err("no local signing capability".to_string())
    }

    fn local_encryption_capability(
        &self,
        _workspace_id: WorkspaceId,
    ) -> Result<LocalEncryptionCapability, String> {
        Err("no local encryption capability".to_string())
    }
}
