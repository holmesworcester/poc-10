//! CLI adapter for projected user reads.

use crate::core::cli::{CliArgs, CliOutput};
use crate::core::command_context::CommandContext;

use super::queries;
use super::rows::UserRow;

pub const USERS_USAGE: &str = "users WORKSPACE_ID_HEX";

pub fn users(ctx: &CommandContext<'_>, args: CliArgs<'_>) -> Result<Vec<UserRow>, String> {
    args.require_len(1, USERS_USAGE)?;
    let workspace_id = decode_hex_32(args.get(0).expect("length checked"), "workspace id")?;
    queries::users_in_workspace(ctx.store(), workspace_id)
}

pub fn users_output(users: &[UserRow]) -> CliOutput {
    if users.is_empty() {
        return CliOutput::line("users: 0");
    }
    let mut lines = vec![format!("users: {}", users.len())];
    for user in users {
        lines.push(format!(
            "{} {} public_key={}",
            encode_hex(&user.user_id),
            user.username,
            encode_hex(&user.public_key),
        ));
    }
    CliOutput::lines(lines)
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
