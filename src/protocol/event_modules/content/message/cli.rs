//! Message CLI: `send` and `messages`.
//!
//! `send` looks up the local endpoint's workspace membership, builds a signed
//! message, and admits it. `messages` is a read-only listing that joins users
//! and content/reaction/file projections so display matches the poc-7 contract
//! without scoped CLI helpers reaching across modules' write paths.

use std::collections::BTreeMap;

use crate::core::cli::{CliArgs, CliCommand, CliOutput};
use crate::core::store::Store;
use crate::protocol::cli::Context;
use crate::protocol::event_modules::content::reaction;
use crate::protocol::event_modules::identity::{endpoint, user};
use crate::protocol::event_modules::types::EventId;
use crate::protocol::event_modules::worker;

use super::types::message_event_id_in_minute;

use super::{commands, queries, schema};

const SEND_USAGE: &str = "send WORKSPACE_ID_HEX TEXT";
const MESSAGES_USAGE: &str = "messages WORKSPACE_ID_HEX [LIMIT]";

pub fn commands() -> Vec<CliCommand<Context>> {
    vec![
        CliCommand {
            name: "send",
            usage: SEND_USAGE,
            help: "Send a message to a workspace.",
            run: run_send_command,
        },
        CliCommand {
            name: "messages",
            usage: MESSAGES_USAGE,
            help: "List messages for a workspace.",
            run: run_messages_command,
        },
    ]
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendSummary {
    pub event_id: EventId,
    pub text: String,
}

impl SendSummary {
    pub fn lines(&self) -> Vec<String> {
        vec![
            format!("event_id: {}", hex_id(self.event_id)),
            format!("text: {}", self.text),
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageDisplay {
    pub index: usize,
    pub message_id: EventId,
    pub author_user_id: EventId,
    pub author_username: String,
    pub created_at_ms: u64,
    pub text: String,
    pub reactions: Vec<String>,
    pub files: Vec<String>,
}

impl MessageDisplay {
    pub fn lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        lines.push(format!(
            "{}. [{}] {}: {}",
            self.index, self.created_at_ms, self.author_username, self.text
        ));
        if !self.reactions.is_empty() {
            lines.push(format!("   reactions: {}", self.reactions.join(" ")));
        }
        for file in &self.files {
            lines.push(format!("   file: {}", file));
        }
        lines.push(format!("   id: {}", hex_id(self.message_id)));
        lines
    }
}

fn run_send_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(2, SEND_USAGE)?;
    let workspace_id = parse_hex_id(args.get(0).expect("length checked"), SEND_USAGE)?;
    let text = args.get(1).expect("length checked").to_string();

    let membership = commands::require_local_membership(&context.store, workspace_id)?;
    let local = endpoint::commands::local_keypair(&context.store)?
        .ok_or_else(|| "local endpoint is missing".to_string())?;

    let timestamp = commands::next_authoring_timestamp(&context.store, workspace_id)?;
    let removal_frontier_id =
        commands::require_active_frontier_id(&context.store, workspace_id)?;
    let event_id_in_minute = message_event_id_in_minute(
        &workspace_id,
        &membership.user_authority_event_id,
        &removal_frontier_id,
        timestamp,
    );
    let leaf = commands::derive_message_leaf(
        &context.store,
        &context.protocol,
        workspace_id,
        removal_frontier_id,
        timestamp,
        event_id_in_minute,
    )?;
    let (expires_at_minute, disappearing_setting_id) =
        commands::workspace_expires_at_minute(&context.store, workspace_id, timestamp)?;
    let send = commands::send(commands::SendMessage {
        workspace_id,
        created_at_ms: timestamp,
        author_user_id: membership.user_authority_event_id,
        signer_endpoint_shared_id: membership.endpoint_shared_id,
        signer_private_key: local.signing_secret,
        removal_frontier_id,
        local_history_node_secret_id: leaf.local_history_node_secret_id,
        leaf_node_secret: leaf.leaf_node_secret,
        expires_at_minute,
        disappearing_setting_id,
        text,
    })?;
    let report = worker::run(
        &context.store,
        &context.protocol,
        worker::AdmitAndDrain {
            output: send,
            batch_size: worker::DEFAULT_READY_BATCH,
        },
    )
    .map_err(|err| format!("admit message: {err}"))?;
    if report.admitted.inserted_events == 0 {
        return Err("message was not admitted".to_string());
    }
    Ok(CliOutput::lines(
        SendSummary {
            event_id: report.value.message_id,
            text: report.value.text,
        }
        .lines(),
    ))
}

fn run_messages_command(context: &mut Context, args: CliArgs<'_>) -> Result<CliOutput, String> {
    if args.values().is_empty() || args.values().len() > 2 {
        return Err(MESSAGES_USAGE.to_string());
    }
    let workspace_id = parse_hex_id(args.get(0).expect("length checked"), MESSAGES_USAGE)?;
    let limit = match args.get(1) {
        Some(value) => value
            .parse::<usize>()
            .map_err(|_| MESSAGES_USAGE.to_string())?,
        None => 0,
    };

    let messages = list_for_display(&context.store, workspace_id, limit)?;
    let mut lines = vec![format!("messages: {}", messages.len())];
    for message in &messages {
        lines.extend(message.lines());
    }
    Ok(CliOutput::lines(lines))
}

pub fn list_for_display(
    store: &Store,
    workspace_id: EventId,
    limit: usize,
) -> Result<Vec<MessageDisplay>, String> {
    let mut messages = visible_message_rows(store, workspace_id)?;
    let total = messages.len();
    let take = if limit == 0 || limit >= total {
        total
    } else {
        limit
    };
    let start = total - take;
    messages.drain(..start);
    let reactions = reactions_grouped_by_message_for_display(store, workspace_id)?;
    let files = files_grouped_by_message_for_display(store, workspace_id)?;
    let mut display = Vec::with_capacity(messages.len());
    for (idx, row) in messages.into_iter().enumerate() {
        let author_username = user_name(store, workspace_id, row.author_user_id)?;
        let reactions_for = reactions.get(&row.message_id).cloned().unwrap_or_default();
        let files_for = files
            .get(&row.message_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .map(|file| file.summary())
            .collect::<Vec<_>>();
        display.push(MessageDisplay {
            index: start + idx + 1,
            message_id: row.message_id,
            author_user_id: row.author_user_id,
            author_username,
            created_at_ms: row.created_at_ms,
            text: row.text,
            reactions: reactions_for,
            files: files_for,
        });
    }
    Ok(display)
}

// `is_deleted_by_author` lives in `commands.rs` (read-side defensive filter).
pub(crate) use commands::is_deleted_by_author;

fn visible_message_rows(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<super::types::MessageRow>, String> {
    let mut by_id = BTreeMap::new();
    for row in queries::list_for_workspace(store, workspace_id)? {
        by_id.insert(row.message_id, row);
    }
    for sealed in sealed_message_rows_for_workspace(store, workspace_id)? {
        if let Some(row) = commands::open_sealed_message_row(store, sealed)? {
            by_id.entry(row.message_id).or_insert(row);
        }
    }
    let mut rows = by_id.into_values().collect::<Vec<_>>();
    rows.sort_by(|a, b| {
        a.created_at_ms
            .cmp(&b.created_at_ms)
            .then_with(|| a.message_id.cmp(&b.message_id))
    });
    rows.into_iter()
        .filter_map(
            |row| match is_deleted_by_author(store, &row.message_id, &row.author_user_id) {
                Ok(false) => Some(Ok(row)),
                Ok(true) => None,
                Err(err) => Some(Err(err)),
            },
        )
        .collect()
}

fn sealed_message_rows_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<schema::SealedMessageRow>, String> {
    store
        .table_rows_with_key_prefix(schema::SEALED_MESSAGES, &workspace_id, usize::MAX)
        .map_err(|err| format!("load sealed messages: {err}"))?
        .into_iter()
        .map(|(key, value)| schema::decode_sealed_message_row(&key, &value))
        .collect()
}

// `open_sealed_message_row` lives in `commands.rs` — the crypto for
// reopening a sealed message belongs alongside the seal-path commands so
// the CLI does not need to import `core::crypto` for display.

fn files_grouped_by_message_for_display(
    store: &Store,
    workspace_id: EventId,
) -> Result<BTreeMap<EventId, Vec<super::super::file::types::FileRow>>, String> {
    let rows = super::super::file::cli::visible_file_rows(store, workspace_id)?;
    let mut grouped: BTreeMap<EventId, Vec<super::super::file::types::FileRow>> = BTreeMap::new();
    for row in rows {
        grouped.entry(row.message_id).or_default().push(row);
    }
    Ok(grouped)
}

fn reactions_grouped_by_message_for_display(
    store: &Store,
    workspace_id: EventId,
) -> Result<BTreeMap<EventId, Vec<String>>, String> {
    let rows = visible_reaction_rows(store, workspace_id)?;
    let mut grouped: BTreeMap<EventId, Vec<(EventId, String)>> = BTreeMap::new();
    for row in rows {
        let entry = grouped.entry(row.target_message_id).or_default();
        let key_pair = (row.author_user_id, row.emoji.clone());
        if !entry.iter().any(|existing| existing == &key_pair) {
            entry.push(key_pair);
        }
    }
    Ok(grouped
        .into_iter()
        .map(|(target, pairs)| (target, pairs.into_iter().map(|(_, emoji)| emoji).collect()))
        .collect())
}

/// All reactions visible to the local store for one workspace, including
/// sealed rows that the local key secret can open. Sorted chronologically by
/// `(created_at_ms, reaction_id)` so callers can group/dedupe deterministically.
pub fn visible_reaction_rows(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<reaction::types::ReactionRow>, String> {
    let mut by_id = BTreeMap::new();
    for row in reaction::queries::list_for_workspace(store, workspace_id)? {
        by_id.insert(row.reaction_id, row);
    }
    for sealed in sealed_reaction_rows_for_workspace(store, workspace_id)? {
        if let Some(row) = reaction::commands::open_sealed_reaction_row(store, sealed)? {
            by_id.entry(row.reaction_id).or_insert(row);
        }
    }

    let mut rows = by_id.into_values().collect::<Vec<_>>();
    rows.sort_by(|a, b| {
        a.created_at_ms
            .cmp(&b.created_at_ms)
            .then_with(|| a.reaction_id.cmp(&b.reaction_id))
    });
    Ok(rows)
}

fn sealed_reaction_rows_for_workspace(
    store: &Store,
    workspace_id: EventId,
) -> Result<Vec<reaction::schema::SealedReactionRow>, String> {
    store
        .table_rows_with_key_prefix(
            reaction::schema::SEALED_REACTIONS,
            &workspace_id,
            usize::MAX,
        )
        .map_err(|err| format!("load sealed reactions: {err}"))?
        .into_iter()
        .map(|(key, value)| reaction::schema::decode_sealed_reaction_row(&key, &value))
        .collect()
}

// `open_sealed_reaction_row` lives in `reaction::commands` so the cli is
// not a crypto site; the visible_reaction_rows iterator below calls into
// it for each sealed row.

pub fn resolve_selector(
    store: &Store,
    workspace_id: EventId,
    selector: &str,
) -> Result<EventId, String> {
    if let Some(rest) = selector.strip_prefix('#') {
        let number: usize = rest
            .parse()
            .map_err(|_| format!("invalid message selector: {selector}"))?;
        if number == 0 {
            return Err(format!("invalid message selector: {selector}"));
        }
        let messages = visible_message_rows(store, workspace_id)?;
        let row = messages
            .get(number - 1)
            .ok_or_else(|| format!("message #{number} does not exist"))?;
        Ok(row.message_id)
    } else {
        parse_hex_id(selector, "MESSAGE_SELECTOR")
    }
}

// CLI authoring helpers (membership lookup, active-frontier resolution,
// next-timestamp, per-event leaf derivation, expires-at computation) live in
// `commands.rs` so peer CLIs and tests can share them. The wrappers below
// keep `message::cli::*` callable as a compatibility surface for the rest of
// the CLI tree.
pub(crate) use commands::require_local_membership as require_membership;
pub(crate) use commands::{
    derive_message_leaf, next_authoring_timestamp as next_timestamp, require_active_frontier_id,
    workspace_expires_at_minute,
};

fn user_name(store: &Store, workspace_id: EventId, user_id: EventId) -> Result<String, String> {
    let key = user::schema::user_key(&workspace_id, &user_id);
    let value = store
        .table_row(user::schema::USERS, &key)
        .map_err(|err| format!("load user: {err}"))?;
    match value {
        Some(value) => {
            let row = user::schema::decode_user_row(&key, &value)?;
            Ok(row.username)
        }
        None => Ok(format!("<{}>", short_id(user_id))),
    }
}

fn short_id(id: EventId) -> String {
    hex_id(id)[..8].to_string()
}

pub(crate) fn parse_hex_id(value: &str, usage: &str) -> Result<EventId, String> {
    if value.len() != 64 {
        return Err(usage.to_string());
    }
    let mut out = [0; 32];
    let bytes = value.as_bytes();
    for idx in 0..32 {
        out[idx] = (hex_value(bytes[idx * 2], usage)? << 4) | hex_value(bytes[idx * 2 + 1], usage)?;
    }
    Ok(out)
}

fn hex_value(byte: u8, usage: &str) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(usage.to_string()),
    }
}

pub fn hex_id(id: EventId) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for byte in id {
        out.push(DIGITS[(byte >> 4) as usize] as char);
        out.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    out
}
