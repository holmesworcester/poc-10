//! CLI adapter for projected user reads.
//!
//! This file owns only argv parsing and text formatting for projected user
//! rows. Runtime draining, handler dispatch, and persistence stay at the root
//! app/runtime boundary.

use crate::core::cli::{decode_hex_32_named as decode_hex_32, encode_hex, CliArgs, CliOutput};
use crate::core::store::Store;

use super::queries;
use super::queries::UserRow;

pub const USERS_USAGE: &str = "users WORKSPACE_ID_HEX";

pub fn users(store: &Store, args: CliArgs<'_>) -> Result<Vec<UserRow>, String> {
    args.require_len(1, USERS_USAGE)?;
    let workspace_id = decode_hex_32(args.get(0).expect("length checked"), "workspace id")?;
    queries::users_in_workspace(store, workspace_id)
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
