//! CLI adapter for sealed message commands and queries.

use crate::core::cli::{CliArgs, CliOutput};
use crate::core::command_context::{CommandContext, CommandOutput};
use crate::core::facts::FactId;
use crate::core::store::Store;
use crate::event_modules::{identity_endpoint_shared, identity_user};

use super::{create, queries};

pub const SEND_USAGE: &str = "send WORKSPACE_ID_HEX TEXT";
pub const MESSAGES_USAGE: &str = "messages WORKSPACE_ID_HEX";

pub fn send(
    ctx: &CommandContext<'_>,
    args: CliArgs<'_>,
) -> Result<CommandOutput<create::SendReceipt>, String> {
    args.require_len(2, SEND_USAGE)?;
    let workspace_id = decode_hex_32(args.get(0).expect("length checked"))?;
    let text = args.get(1).expect("length checked");
    create::send_message(ctx, workspace_id, text)
}

pub fn send_output(receipt: &create::SendReceipt, text: &str) -> CliOutput {
    CliOutput::lines(vec![
        format!("workspace_id: {}", encode_hex(&receipt.workspace_id)),
        format!("message_id: {}", encode_hex(&receipt.message_fact_id)),
        format!("created_at_ms: {}", receipt.created_at_ms),
        format!("text: {text}"),
    ])
}

pub fn messages(ctx: &CommandContext<'_>, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(1, MESSAGES_USAGE)?;
    let workspace_id = decode_hex_32(args.get(0).expect("length checked"))?;
    let messages = queries::opened_messages(ctx.store(), workspace_id)?;
    let mut lines = vec![format!("messages: {}", messages.len())];
    for message in messages {
        let author = author_name(ctx.store(), workspace_id, message.signer_id)?
            .unwrap_or_else(|| short_hex(&message.signer_id));
        lines.push(format!("{author}: {}", message.text));
    }
    Ok(CliOutput::lines(lines))
}

fn author_name(
    store: &Store,
    workspace_id: FactId,
    signer_endpoint_id: FactId,
) -> Result<Option<String>, String> {
    for peer in identity_endpoint_shared::queries::peers_in_workspace(store, workspace_id)? {
        if peer.endpoint_id != signer_endpoint_id {
            continue;
        }
        let user_key = identity_user::rows::user_key(&workspace_id, &peer.user_authority_event_id);
        let Some(value) = store
            .table_row(identity_user::rows::USER_ROWS, &user_key)
            .map_err(|err| format!("read user row: {err}"))?
        else {
            return Ok(None);
        };
        let row = identity_user::rows::decode_user_row(&user_key, &value)?;
        return Ok(Some(row.username));
    }
    Ok(None)
}

fn decode_hex_32(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("id must be 64 hex characters".to_string());
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
    let mut out = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write;
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn short_hex(bytes: &[u8; 32]) -> String {
    encode_hex(bytes)[..12].to_string()
}
