//! CLI for workspace user rows.
//!
//! `users` is a read-only view of the user leaf table for one workspace. It
//! does not create users or coordinate invite acceptance; those workflows remain
//! in commands or the identity root CLI where their cross-leaf dependencies are
//! visible.

use crate::core::commands::{CliArgs, CliCommand, CliOutput};
use crate::legacy::protocol::commands::Context;
use crate::legacy::protocol::event_modules::identity::invite;
use crate::legacy::protocol::event_modules::types::EventId;

const USERS_USAGE: &str = "users WORKSPACE_ID_HEX";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![CliCommand {
        name: "users",
        usage: USERS_USAGE,
        help: "List users in a workspace.",
        run: run_users_command,
    }]
}

fn run_users_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(1, USERS_USAGE)?;
    let workspace_id = decode_hex_32(args.get(0).expect("length checked"))?;
    let mut lines = Vec::new();
    for (key, value) in context
        .store
        .table_rows_with_key_prefix(super::rows::USERS, &workspace_id, usize::MAX)
        .map_err(|err| format!("load users: {err}"))?
    {
        let row = super::rows::decode_user_row(&key, &value)?;
        lines.push(format!("{} {}", encode_hex(&row.user_id), row.username));
    }
    Ok(CliOutput::lines(lines))
}

fn encode_hex(bytes: &[u8; 32]) -> String {
    invite::commands::encode_hex(bytes)
}

fn decode_hex_32(value: &str) -> Result<EventId, String> {
    if value.len() != 64 {
        return Err(USERS_USAGE.to_string());
    }
    let mut out = [0; 32];
    let bytes = value.as_bytes();
    for idx in 0..32 {
        out[idx] = (hex_value(bytes[idx * 2])? << 4) | hex_value(bytes[idx * 2 + 1])?;
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(USERS_USAGE.to_string()),
    }
}
