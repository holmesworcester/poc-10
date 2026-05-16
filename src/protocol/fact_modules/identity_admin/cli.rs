//! CLI adapter for admin grant commands.

use crate::core::cli::{CliArgs, CliOutput};
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

fn decode_hex_32(value: &str, label: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err(format!("{label} must be 64 hex characters"));
    }
    let mut out = [0u8; 32];
    let bytes = value.as_bytes();
    for index in 0..32 {
        let hi = hex_nibble(bytes[index * 2])?;
        let lo = hex_nibble(bytes[index * 2 + 1])?;
        out[index] = (hi << 4) | lo;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("hex value contains non-hex character".to_string()),
    }
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in bytes {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}
