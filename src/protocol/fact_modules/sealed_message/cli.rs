//! CLI adapter for sealed message commands and queries.

use crate::core::cli::{CliArgs, CliOutput};
use crate::core::command_context::{CommandContext, CommandOutput};
use crate::core::facts::FactId;
use crate::core::store::Store;
use crate::protocol::fact_modules::identity_workspace;
use crate::protocol::fact_modules::{identity_endpoint, identity_endpoint_shared, identity_user};

use super::{create, queries};

pub const SEND_USAGE: &str = "send WORKSPACE_ID_HEX TEXT";
pub const MESSAGES_USAGE: &str = "messages WORKSPACE_ID_HEX";
pub const VIEW_USAGE: &str = "view [WORKSPACE_ID_HEX]";

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
    for (index, message) in messages.into_iter().enumerate() {
        let author = author_name(ctx.store(), workspace_id, message.signer_id)?
            .unwrap_or_else(|| short_hex(&message.signer_id));
        lines.push(format!(
            "{}. [{}] {author}: {}",
            index + 1,
            message.created_at_ms,
            message.text
        ));
    }
    Ok(CliOutput::lines(lines))
}

pub fn view(ctx: &CommandContext<'_>, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let workspace_id = match args.values() {
        [] => selected_workspace_id(ctx)?,
        [value] => decode_hex_32(value)?,
        _ => return Err(VIEW_USAGE.to_string()),
    };

    let local = identity_endpoint::queries::local_endpoint_public(ctx.store())?
        .ok_or_else(|| "local endpoint is missing".to_string())?;
    let local_memberships = identity_workspace::local_membership::local_memberships(ctx.store())?;
    if !local_memberships
        .iter()
        .any(|membership| membership.workspace_id == workspace_id)
    {
        return Err("local endpoint has not joined this workspace".to_string());
    }

    let workspace = identity_workspace::queries::workspace_by_id(ctx.store(), workspace_id)?;
    let users = identity_user::queries::users_in_workspace(ctx.store(), workspace_id)?;
    let peers = identity_endpoint_shared::queries::peers_in_workspace(ctx.store(), workspace_id)?;
    let messages = queries::opened_messages(ctx.store(), workspace_id)?;

    let mut username_by_user = std::collections::BTreeMap::new();
    for user in &users {
        username_by_user.insert(user.user_id, user.username.clone());
    }
    let mut username_by_endpoint = std::collections::BTreeMap::new();
    for peer in &peers {
        if let Some(username) = username_by_user.get(&peer.user_authority_event_id) {
            username_by_endpoint.insert(peer.endpoint_id, username.clone());
        }
    }

    let mut lines = Vec::new();
    lines.push("IDENTITY:".to_string());
    lines.push(format!("  endpoint_id: {}", encode_hex(&local.endpoint)));
    lines.push(format!(
        "  signing_public_key: {}",
        encode_hex(&local.signing_public_key)
    ));
    lines.push(String::new());
    lines.push("WORKSPACE:".to_string());
    lines.push(format!("  {}", workspace.name));
    lines.push(String::new());
    lines.push("  USERS:".to_string());
    if peers.is_empty() {
        lines.push("    (none)".to_string());
    } else {
        for peer in peers {
            let username = username_by_user
                .get(&peer.user_authority_event_id)
                .cloned()
                .unwrap_or_else(|| short_hex(&peer.user_authority_event_id));
            let label = format!("{}/{}", username, peer.device_name);
            if peer.endpoint_id == local.endpoint {
                lines.push(format!("    {label} (you)"));
            } else {
                lines.push(format!("    {label}"));
            }
        }
    }
    lines.push(String::new());
    lines.push(format!("  {}", "\u{2500}".repeat(40)));
    lines.push(String::new());

    if messages.is_empty() {
        lines.push("    (no messages)".to_string());
    } else {
        let mut last_author = None;
        for (index, message) in messages.iter().enumerate() {
            if last_author != Some(message.signer_id) {
                if index > 0 {
                    lines.push(String::new());
                }
                let author = username_by_endpoint
                    .get(&message.signer_id)
                    .or_else(|| username_by_user.get(&message.author_user_id))
                    .cloned()
                    .unwrap_or_else(|| short_hex(&message.signer_id));
                lines.push(format!("    {author} [now]"));
                last_author = Some(message.signer_id);
            }
            lines.push(format!("      {}. {}", index + 1, message.text));
        }
    }

    Ok(CliOutput::lines(lines))
}

fn selected_workspace_id(ctx: &CommandContext<'_>) -> Result<FactId, String> {
    let memberships = identity_workspace::local_membership::local_memberships(ctx.store())?;
    match memberships.as_slice() {
        [] => Err("no joined workspaces; create or accept one first".to_string()),
        [membership] => Ok(membership.workspace_id),
        _ => Err("select a workspace: pass WORKSPACE_ID_HEX".to_string()),
    }
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
