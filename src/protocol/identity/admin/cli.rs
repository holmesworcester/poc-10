//! CLI adapter for admin grant commands.
//!
//! This file owns only argv parsing and text formatting. Admin fact
//! construction lives in `commands.rs`; runtime draining, handler dispatch,
//! and persistence stay at the root app/runtime boundary.

use crate::core::cli::{decode_hex_32_named as decode_hex_32, encode_hex, CliArgs, CliOutput};
use crate::core::command_context::{CommandContext, CommandOutput};

use super::commands;

pub const GRANT_ADMIN_USAGE: &str = "grant-admin WORKSPACE_ID_HEX USER_ID_HEX";

pub fn grant_admin(
    ctx: &CommandContext<'_>,
    args: CliArgs<'_>,
) -> Result<CommandOutput<commands::GrantAdminReceipt>, String> {
    let workspace = args.get(0).ok_or_else(|| GRANT_ADMIN_USAGE.to_string())?;
    let user = args.get(1).ok_or_else(|| GRANT_ADMIN_USAGE.to_string())?;
    commands::grant_admin(
        ctx,
        commands::GrantAdmin {
            created_at_ms: ctx.next_timestamp(),
            workspace_id: decode_hex_32(workspace, "workspace id")?,
            user_id: decode_hex_32(user, "user id")?,
        },
    )
}

pub fn grant_admin_output(receipt: &commands::GrantAdminReceipt) -> CliOutput {
    CliOutput::line(format!("admin_id: {}", encode_hex(&receipt.admin_id)))
}
