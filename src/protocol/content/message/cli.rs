//! CLI adapter for opened content commands and queries.
//!
//! This file owns CLI-facing concerns for the message surface: argv parsing,
//! selector resolution, and text formatting. Runtime draining,
//! projection, handler dispatch, and persistence stay in the root app/runtime
//! boundary. Local payload file reads/writes go through core helpers; they do
//! not happen through direct `std::fs` calls here.

use std::collections::BTreeMap;
use std::path::Path;

use crate::core::cli::{
    decode_hex_32, encode_hex_32, read_file_bytes, write_file_bytes, CliArgs, CliOutput,
};
use crate::core::command_context::{CommandContext, CommandOutput};
use crate::core::crypto::{self, XChaCha20Poly1305Key, XChaCha20Poly1305Nonce};
use crate::core::fact_store::persisted_facts;
use crate::core::facts::{Fact, FactId};
use crate::core::store::Store;
use crate::protocol::auth;
use crate::protocol::content::{file, file_slice, message, message_deletion, reaction};

use super::queries;

pub const SEND_USAGE: &str = "send WORKSPACE_ID_HEX TEXT";
pub const GENERATE_USAGE: &str = "generate WORKSPACE_ID_HEX COUNT MESSAGE_TEXT_BYTES";
pub const REACT_USAGE: &str = "react WORKSPACE_ID_HEX MESSAGE_SELECTOR EMOJI";
pub const SEND_FILE_USAGE: &str = "send-file WORKSPACE_ID_HEX TEXT --file PATH [--mime MIME]";
pub const FILES_USAGE: &str = "files WORKSPACE_ID_HEX [LIMIT]";
pub const SAVE_FILE_USAGE: &str = "save-file WORKSPACE_ID_HEX FILE_SELECTOR OUT_PATH";
pub const DELETE_MESSAGE_USAGE: &str = "delete-message WORKSPACE_ID_HEX MESSAGE_SELECTOR";
pub const MESSAGES_USAGE: &str = "messages WORKSPACE_ID_HEX";
pub const CONTENT_COUNT_USAGE: &str = "content-count WORKSPACE_ID_HEX";
pub const VIEW_USAGE: &str = "view [WORKSPACE_ID_HEX]";

const DEFAULT_MIME: &str = "application/octet-stream";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactReceipt {
    pub workspace_id: FactId,
    pub reaction_fact_id: FactId,
    pub target_message_id: FactId,
    pub emoji: String,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendFileReceipt {
    pub workspace_id: FactId,
    pub message_fact_id: FactId,
    pub file_fact_id: FactId,
    pub file_id: FactId,
    pub filename: String,
    pub mime: String,
    pub blob_bytes: u64,
    pub total_slices: u32,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteMessageReceipt {
    pub workspace_id: FactId,
    pub deletion_fact_id: FactId,
    pub target_message_id: FactId,
}

pub fn send(
    ctx: &CommandContext<'_>,
    args: CliArgs<'_>,
) -> Result<CommandOutput<message::create::SendReceipt>, String> {
    args.require_len(2, SEND_USAGE)?;
    let workspace_id = decode_id(args.get(0).expect("length checked"))?;
    let text = args.get(1).expect("length checked");
    message::create::send_message(ctx, workspace_id, text)
}

pub fn send_output(receipt: &message::create::SendReceipt, text: &str) -> CliOutput {
    CliOutput::lines(vec![
        format!("workspace_id: {}", encode_hex_32(&receipt.workspace_id)),
        format!("fact_id: {}", encode_hex_32(&receipt.message_fact_id)),
        format!("message_id: {}", encode_hex_32(&receipt.message_fact_id)),
        format!("created_at_ms: {}", receipt.created_at_ms),
        format!("text: {text}"),
    ])
}

pub fn generate(
    ctx: &CommandContext<'_>,
    args: CliArgs<'_>,
) -> Result<CommandOutput<message::create::GenerateReceipt>, String> {
    args.require_len(3, GENERATE_USAGE)?;
    let workspace_id = decode_id(args.get(0).expect("length checked"))?;
    let count = args.parse_positive_usize(1, GENERATE_USAGE)?;
    let message_text_bytes = args.parse_positive_usize(2, GENERATE_USAGE)?;
    message::create::generate_messages(ctx, workspace_id, count, message_text_bytes)
}

pub fn generated_output(
    receipt: &message::create::GenerateReceipt,
    applied_facts: usize,
) -> CliOutput {
    CliOutput::lines(vec![
        format!("workspace_id: {}", encode_hex_32(&receipt.workspace_id)),
        format!("generated_facts: {}", receipt.generated_facts),
        format!("applied_facts: {applied_facts}"),
        format!("message_text_bytes: {}", receipt.message_text_bytes),
        format!("first_timestamp: {}", receipt.first_timestamp),
        format!("last_timestamp: {}", receipt.last_timestamp),
    ])
}

pub fn react(
    ctx: &CommandContext<'_>,
    args: CliArgs<'_>,
) -> Result<CommandOutput<ReactReceipt>, String> {
    args.require_len(3, REACT_USAGE)?;
    let workspace_id = decode_id(args.get(0).expect("length checked"))?;
    let target = resolve_message_selector(ctx.store(), workspace_id, args.get(1).unwrap())?;
    let emoji = args.get(2).unwrap().trim();
    if emoji.is_empty() {
        return Err("reaction emoji must not be empty".to_string());
    }
    if emoji.len()
        > reaction::fact::REACTION_CIPHERTEXT_BYTES - crypto::XCHACHA20_POLY1305_TAG_BYTES
    {
        return Err("reaction emoji is too long".to_string());
    }

    let author_user_id = local_author_user_id(ctx.store(), workspace_id)?;
    let encryption = ctx.local_encryption_capability(workspace_id)?;
    let created_at_ms = ctx.next_timestamp();
    let nonce = deterministic_nonce(b"topo:reaction-nonce:v1", workspace_id, created_at_ms);
    let ciphertext = seal_bytes(
        &encryption.key_secret,
        &nonce,
        emoji.as_bytes(),
        "reaction emoji",
    )?;
    if ciphertext.len() > reaction::fact::REACTION_CIPHERTEXT_BYTES {
        return Err("reaction emoji is too long".to_string());
    }
    let reaction = reaction::fact::ContentReactionFact {
        workspace_id,
        created_at_ms,
        target_message_id: target.message_id,
        author_user_id,
        signer_id: [0; 32],
        signer_public_key: [0; 32],
        nonce,
        ciphertext: reaction::fact::ReactionCiphertext::new(&ciphertext)
            .map_err(|err| format!("reaction ciphertext: {err}"))?,
        signature: [0; crypto::ED25519_SIGNATURE_BYTES],
    };
    let fact = signed_reaction_fact(ctx, workspace_id, created_at_ms, reaction)?;
    Ok(CommandOutput::new(ReactReceipt {
        workspace_id,
        reaction_fact_id: fact.id,
        target_message_id: target.message_id,
        emoji: emoji.to_string(),
        created_at_ms,
    })
    .with_facts(vec![fact]))
}

pub fn react_output(receipt: &ReactReceipt) -> CliOutput {
    CliOutput::lines(vec![
        format!("workspace_id: {}", encode_hex_32(&receipt.workspace_id)),
        format!("reaction_id: {}", encode_hex_32(&receipt.reaction_fact_id)),
        format!(
            "target_message_id: {}",
            encode_hex_32(&receipt.target_message_id)
        ),
        format!("created_at_ms: {}", receipt.created_at_ms),
        format!("emoji: {}", receipt.emoji),
    ])
}

pub fn send_file(
    ctx: &CommandContext<'_>,
    args: CliArgs<'_>,
) -> Result<CommandOutput<SendFileReceipt>, String> {
    let parsed = parse_send_file_args(args)?;
    let payload = read_file_bytes(&parsed.path)?;
    let filename = parsed
        .path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| "file path must have a utf-8 filename".to_string())?
        .to_string();
    let message_output = message::create::send_message(ctx, parsed.workspace_id, &parsed.text)?;
    let message_receipt = message_output.receipt.clone();
    let author_user_id = local_author_user_id(ctx.store(), parsed.workspace_id)?;
    let created_at_ms = message_receipt.created_at_ms.saturating_add(1);
    let encryption = ctx.local_encryption_capability(parsed.workspace_id)?;
    let total_slices = if payload.is_empty() {
        0
    } else {
        payload
            .len()
            .div_ceil(file_slice::fact::FILE_SLICE_PLAINTEXT_BYTES) as u32
    };
    let encrypted_slices = encrypted_file_slices(
        &payload,
        &encryption.key_secret,
        parsed.workspace_id,
        message_receipt.message_fact_id,
        created_at_ms,
    )?;
    let root_hash = encrypted_blob_root_hash(&encrypted_slices);
    let file_id = file_id_for(
        parsed.workspace_id,
        message_receipt.message_fact_id,
        created_at_ms,
        &filename,
        &root_hash,
    );
    let metadata_nonce = deterministic_nonce_for_parts(
        b"topo:file-metadata-nonce:v1",
        &[&parsed.workspace_id, &file_id],
    );
    let sealed_metadata = seal_bytes(
        &encryption.key_secret,
        &metadata_nonce,
        &encode_file_metadata(&filename, &parsed.mime)?,
        "file metadata",
    )?;
    let descriptor = file::fact::ContentFileFact {
        workspace_id: parsed.workspace_id,
        created_at_ms,
        message_id: message_receipt.message_fact_id,
        author_user_id,
        signer_id: [0; 32],
        signer_public_key: [0; 32],
        file_id,
        blob_bytes: payload.len() as u64,
        total_slices,
        slice_bytes: file_slice::fact::FILE_SLICE_PLAINTEXT_BYTES as u32,
        root_hash,
        sealed_metadata: file::fact::SealedMetadata::new(&sealed_metadata)
            .map_err(|err| format!("file metadata: {err}"))?,
        signature: [0; crypto::ED25519_SIGNATURE_BYTES],
    };
    let descriptor_fact = signed_file_fact(ctx, parsed.workspace_id, created_at_ms, descriptor)?;
    let mut facts = message_output.effects.facts;
    facts.push(descriptor_fact.clone());
    for encrypted in encrypted_slices {
        let slice = file_slice::fact::ContentFileSliceFact {
            workspace_id: parsed.workspace_id,
            created_at_ms: encrypted.created_at_ms,
            file_id,
            slice_index: encrypted.slice_index,
            signer_id: [0; 32],
            signer_public_key: [0; 32],
            ciphertext: file_slice::fact::FileSliceCiphertext::new(&encrypted.ciphertext)
                .map_err(|err| format!("file slice ciphertext: {err}"))?,
            signature: [0; crypto::ED25519_SIGNATURE_BYTES],
        };
        facts.push(signed_file_slice_fact(
            ctx,
            parsed.workspace_id,
            slice.created_at_ms,
            slice,
        )?);
    }

    Ok(CommandOutput::new(SendFileReceipt {
        workspace_id: parsed.workspace_id,
        message_fact_id: message_receipt.message_fact_id,
        file_fact_id: descriptor_fact.id,
        file_id,
        filename,
        mime: parsed.mime,
        blob_bytes: payload.len() as u64,
        total_slices,
        created_at_ms,
    })
    .with_facts(facts))
}

pub fn send_file_output(receipt: &SendFileReceipt) -> CliOutput {
    CliOutput::lines(vec![
        format!("workspace_id: {}", encode_hex_32(&receipt.workspace_id)),
        format!("message_id: {}", encode_hex_32(&receipt.message_fact_id)),
        format!("file_fact_id: {}", encode_hex_32(&receipt.file_fact_id)),
        format!("file_id: {}", encode_hex_32(&receipt.file_id)),
        format!("created_at_ms: {}", receipt.created_at_ms),
        format!("filename: {}", receipt.filename),
        format!("mime: {}", receipt.mime),
        format!("blob_bytes: {}", receipt.blob_bytes),
        format!("total_slices: {}", receipt.total_slices),
    ])
}

pub fn delete_message(
    ctx: &CommandContext<'_>,
    args: CliArgs<'_>,
) -> Result<CommandOutput<DeleteMessageReceipt>, String> {
    args.require_len(2, DELETE_MESSAGE_USAGE)?;
    let workspace_id = decode_id(args.get(0).expect("length checked"))?;
    let target = resolve_message_selector(ctx.store(), workspace_id, args.get(1).unwrap())?;
    let output = message_deletion::commands::delete_message(
        ctx,
        workspace_id,
        target.message_id,
        target.frontier_id,
        target.minute,
        target.author_user_id,
    )?;
    let receipt = output.receipt.clone();
    Ok(CommandOutput::new(DeleteMessageReceipt {
        workspace_id,
        deletion_fact_id: receipt.deletion_fact_id,
        target_message_id: target.message_id,
    })
    .with_facts(output.effects.facts))
}

pub fn delete_message_output(receipt: &DeleteMessageReceipt) -> CliOutput {
    CliOutput::lines(vec![
        format!("workspace_id: {}", encode_hex_32(&receipt.workspace_id)),
        format!("fact_id: {}", encode_hex_32(&receipt.deletion_fact_id)),
        format!(
            "target_message_id: {}",
            encode_hex_32(&receipt.target_message_id)
        ),
    ])
}

pub fn messages(ctx: &CommandContext<'_>, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(1, MESSAGES_USAGE)?;
    let workspace_id = decode_id(args.get(0).expect("length checked"))?;
    let messages = queries::opened_messages(ctx.store(), workspace_id)?;
    let reactions = reactions_by_message(ctx.store(), workspace_id)?;
    let files = files_by_message(ctx.store(), workspace_id)?;
    let mut lines = vec![format!("messages: {}", messages.len())];
    for (index, message) in messages.into_iter().enumerate() {
        let author = author_name(ctx.store(), workspace_id, message.signer_id)?
            .or_else(|| {
                user_name(ctx.store(), workspace_id, message.author_user_id)
                    .ok()
                    .flatten()
            })
            .unwrap_or_else(|| short_hex(&message.signer_id));
        lines.push(format!(
            "{}. [{}] {author}: {}",
            index + 1,
            message.created_at_ms,
            message.text
        ));
        lines.push(format!("   id: {}", encode_hex_32(&message.message_id)));
        if let Some(reactions) = reactions.get(&message.message_id) {
            let emojis = reactions
                .iter()
                .map(|reaction| reaction.emoji.as_str())
                .collect::<Vec<_>>()
                .join(" ");
            lines.push(format!("   reactions: {emojis}"));
        }
        if let Some(files) = files.get(&message.message_id) {
            for file in files {
                lines.push(format!(
                    "   file: {} ({})",
                    file.filename,
                    format_bytes(file.blob_bytes)
                ));
            }
        }
    }
    Ok(CliOutput::lines(lines))
}

pub fn content_count(
    ctx: &CommandContext<'_>,
    args: CliArgs<'_>,
) -> Result<queries::ContentCount, String> {
    args.require_len(1, CONTENT_COUNT_USAGE)?;
    let workspace_id = decode_id(args.get(0).expect("length checked"))?;
    queries::count_for_workspace(ctx.store(), workspace_id)
}

pub fn content_count_output(count: queries::ContentCount) -> CliOutput {
    CliOutput::lines(vec![
        format!("content_messages: {}", count.content_messages),
        format!("message_facts: {}", count.content_messages),
        format!("message_payload_bytes: {}", count.message_payload_bytes),
        format!("max_message_timestamp: {}", count.max_created_at_ms),
    ])
}

pub fn files(ctx: &CommandContext<'_>, args: CliArgs<'_>) -> Result<CliOutput, String> {
    if args.values().is_empty() || args.values().len() > 2 {
        return Err(FILES_USAGE.to_string());
    }
    let workspace_id = decode_id(args.get(0).expect("length checked"))?;
    let limit = args
        .get(1)
        .map(|value| value.parse::<usize>().map_err(|_| FILES_USAGE.to_string()))
        .transpose()?
        .unwrap_or(usize::MAX);
    let mut rows = visible_files(ctx.store(), workspace_id)?;
    rows.truncate(limit);
    let mut lines = vec![format!("FILES ({} total):", rows.len())];
    for (index, row) in rows.iter().enumerate() {
        let status = if row.slices_received >= row.total_slices {
            "\u{2714}"
        } else {
            "\u{23f3}"
        };
        let suffix = if row.slices_received >= row.total_slices {
            format!("({})", format_bytes(row.blob_bytes))
        } else {
            let pct = if row.total_slices == 0 {
                100
            } else {
                row.slices_received.saturating_mul(100) / row.total_slices
            };
            format!("({}, {pct}%)", format_bytes(row.blob_bytes))
        };
        lines.push(format!(
            "  {}. {status}  {} {suffix}",
            index + 1,
            row.filename
        ));
    }
    Ok(CliOutput::lines(lines))
}

pub fn save_file(ctx: &CommandContext<'_>, args: CliArgs<'_>) -> Result<CliOutput, String> {
    args.require_len(3, SAVE_FILE_USAGE)?;
    let workspace_id = decode_id(args.get(0).expect("length checked"))?;
    let file = resolve_file_selector(ctx.store(), workspace_id, args.get(1).unwrap())?;
    if file.slices_received < file.total_slices {
        return Err(format!(
            "file incomplete: have {}/{} slices",
            file.slices_received, file.total_slices
        ));
    }
    let mut bytes = Vec::new();
    let message = queries::content_message_row(ctx.store(), workspace_id, file.message_id)?
        .ok_or_else(|| "file parent message is not visible".to_string())?;
    let key = local_content_key(
        ctx.store(),
        workspace_id,
        message.frontier_id,
        message.minute,
    )?;
    let mut encrypted_blob = Vec::new();
    for slice in file_slices(ctx.store(), workspace_id, file.file_id)? {
        encrypted_blob.extend_from_slice(&slice.ciphertext);
        let nonce = file_slice_nonce(
            workspace_id,
            file.message_id,
            file.created_at_ms,
            slice.slice_index,
        );
        let plaintext = open_bytes(&key, &nonce, &slice.ciphertext, "file slice")?;
        bytes.extend_from_slice(&plaintext);
    }
    let actual_root_hash = crypto::hash(&encrypted_blob);
    if actual_root_hash != file.root_hash {
        return Err("file encrypted root hash mismatch".to_string());
    }
    bytes.truncate(file.blob_bytes as usize);
    write_file_bytes(args.get(2).unwrap(), &bytes)?;
    Ok(CliOutput::lines(vec![
        format!("workspace_id: {}", encode_hex_32(&workspace_id)),
        format!("file_fact_id: {}", encode_hex_32(&file.file_fact_id)),
        format!("filename: {}", file.filename),
        format!("bytes_written: {}", bytes.len()),
    ]))
}

pub fn view(ctx: &CommandContext<'_>, args: CliArgs<'_>) -> Result<CliOutput, String> {
    let workspace_id = match args.values() {
        [] => selected_workspace_id(ctx)?,
        [value] => decode_id(value)?,
        _ => return Err(VIEW_USAGE.to_string()),
    };

    let local = auth::endpoint::queries::local_endpoint_public(ctx.store())?
        .ok_or_else(|| "local endpoint is missing".to_string())?;
    let local_memberships = auth::workspace::queries::local_memberships(ctx.store())?;
    if !local_memberships
        .iter()
        .any(|membership| membership.workspace_id == workspace_id)
    {
        return Err("local endpoint has not joined this workspace".to_string());
    }

    let workspace = auth::workspace::queries::workspace_by_id(ctx.store(), workspace_id)?;
    let users = auth::user::queries::users_in_workspace(ctx.store(), workspace_id)?;
    let peers = auth::endpoint_shared::queries::peers_in_workspace(ctx.store(), workspace_id)?;
    let messages = queries::opened_messages(ctx.store(), workspace_id)?;
    let reactions = reactions_by_message(ctx.store(), workspace_id)?;
    let files = files_by_message(ctx.store(), workspace_id)?;

    let mut username_by_user = BTreeMap::new();
    for user in &users {
        username_by_user.insert(user.user_id, user.username.clone());
    }
    let mut username_by_endpoint = BTreeMap::new();
    for peer in &peers {
        if let Some(username) = username_by_user.get(&peer.user_authority_fact_id) {
            username_by_endpoint.insert(peer.endpoint_id, username.clone());
        }
    }

    let mut lines = Vec::new();
    lines.push("IDENTITY:".to_string());
    lines.push(format!("  endpoint_id: {}", encode_hex_32(&local.endpoint)));
    lines.push(format!(
        "  signing_public_key: {}",
        encode_hex_32(&local.signing_public_key)
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
                .get(&peer.user_authority_fact_id)
                .cloned()
                .unwrap_or_else(|| short_hex(&peer.user_authority_fact_id));
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
            if let Some(reactions) = reactions.get(&message.message_id) {
                for reaction in reactions {
                    let author = username_by_user
                        .get(&reaction.author_user_id)
                        .cloned()
                        .unwrap_or_else(|| short_hex(&reaction.author_user_id));
                    lines.push(format!("         {} {author}", reaction.emoji));
                }
            }
            if let Some(files) = files.get(&message.message_id) {
                for file in files {
                    let status = if file.slices_received >= file.total_slices {
                        "\u{2714}"
                    } else {
                        "\u{23f3}"
                    };
                    lines.push(format!(
                        "         {status}  {} ({})",
                        file.filename,
                        format_bytes(file.blob_bytes)
                    ));
                }
            }
        }
    }

    Ok(CliOutput::lines(lines))
}

fn selected_workspace_id(ctx: &CommandContext<'_>) -> Result<FactId, String> {
    let memberships = auth::workspace::queries::local_memberships(ctx.store())?;
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
    for peer in auth::endpoint_shared::queries::peers_in_workspace(store, workspace_id)? {
        if peer.endpoint_id != signer_endpoint_id {
            continue;
        }
        return user_name(store, workspace_id, peer.user_authority_fact_id);
    }
    Ok(None)
}

fn user_name(
    store: &Store,
    workspace_id: FactId,
    user_id: FactId,
) -> Result<Option<String>, String> {
    let user_key = auth::user::rows::user_key(&workspace_id, &user_id);
    let Some(value) = store
        .table_row(auth::user::rows::USER_ROWS, &user_key)
        .map_err(|err| format!("read user row: {err}"))?
    else {
        return Ok(None);
    };
    let row = auth::user::rows::decode_user_row(&user_key, &value)?;
    Ok(Some(row.username))
}

fn local_author_user_id(store: &Store, workspace_id: FactId) -> Result<FactId, String> {
    auth::workspace::queries::local_membership(store, workspace_id)?
        .map(|membership| membership.user_authority_fact_id)
        .ok_or_else(|| "local endpoint has not joined this workspace".to_string())
}

#[derive(Debug, Clone)]
struct MessageSelection {
    message_id: FactId,
    frontier_id: FactId,
    minute: u64,
    author_user_id: FactId,
}

fn resolve_message_selector(
    store: &Store,
    workspace_id: FactId,
    selector: &str,
) -> Result<MessageSelection, String> {
    if let Some(index) = selector.strip_prefix('#') {
        let index = index
            .parse::<usize>()
            .map_err(|_| "message selector must be #N or a message id".to_string())?;
        if index == 0 {
            return Err("message selector index starts at #1".to_string());
        }
        let messages = queries::opened_messages(store, workspace_id)?;
        let message = messages
            .get(index - 1)
            .ok_or_else(|| "message selector is out of range".to_string())?;
        let row = queries::content_message_row(store, workspace_id, message.message_id)?
            .ok_or_else(|| "message selector did not match a visible message".to_string())?;
        return Ok(MessageSelection {
            message_id: message.message_id,
            frontier_id: row.frontier_id,
            minute: row.minute,
            author_user_id: row.author_user_id,
        });
    }
    let message_id = decode_id(selector)?;
    if let Some(row) = queries::content_message_row(store, workspace_id, message_id)? {
        return Ok(MessageSelection {
            message_id,
            frontier_id: row.frontier_id,
            minute: row.minute,
            author_user_id: row.author_user_id,
        });
    }
    Err("message selector did not match a visible message".to_string())
}

#[derive(Debug, Clone)]
struct ParsedSendFile {
    workspace_id: FactId,
    text: String,
    path: std::path::PathBuf,
    mime: String,
}

fn parse_send_file_args(args: CliArgs<'_>) -> Result<ParsedSendFile, String> {
    let values = args.values();
    if values.len() < 4 {
        return Err(SEND_FILE_USAGE.to_string());
    }
    let workspace_id = decode_id(&values[0])?;
    let text = values[1].clone();
    let mut path = None;
    let mut mime = DEFAULT_MIME.to_string();
    let mut idx = 2;
    while idx < values.len() {
        match values[idx].as_str() {
            "--file" => {
                let value = values
                    .get(idx + 1)
                    .ok_or_else(|| SEND_FILE_USAGE.to_string())?;
                path = Some(Path::new(value).to_path_buf());
                idx += 2;
            }
            "--mime" => {
                let value = values
                    .get(idx + 1)
                    .ok_or_else(|| SEND_FILE_USAGE.to_string())?;
                mime = value.clone();
                idx += 2;
            }
            _ => return Err(SEND_FILE_USAGE.to_string()),
        }
    }
    let path = path.ok_or_else(|| SEND_FILE_USAGE.to_string())?;
    Ok(ParsedSendFile {
        workspace_id,
        text,
        path,
        mime,
    })
}

#[derive(Debug, Clone)]
struct FileDisplayRow {
    file_fact_id: FactId,
    file_id: FactId,
    message_id: FactId,
    created_at_ms: u64,
    filename: String,
    blob_bytes: u64,
    total_slices: u32,
    slices_received: u32,
    root_hash: [u8; 32],
}

#[derive(Debug, Clone)]
struct ReactionDisplayRow {
    created_at_ms: u64,
    reaction_id: FactId,
    author_user_id: FactId,
    emoji: String,
}

fn reactions_by_message(
    store: &Store,
    workspace_id: FactId,
) -> Result<BTreeMap<FactId, Vec<ReactionDisplayRow>>, String> {
    let mut grouped: BTreeMap<FactId, Vec<ReactionDisplayRow>> = BTreeMap::new();
    for row in reaction::rows::reaction_rows_for_workspace(store, workspace_id)? {
        let Some(message) =
            queries::content_message_row(store, workspace_id, row.target_message_id)?
        else {
            continue;
        };
        let key = local_content_key(store, workspace_id, message.frontier_id, message.minute)?;
        let plaintext = open_bytes(&key, &row.nonce, &row.ciphertext, "reaction emoji")?;
        let emoji = String::from_utf8(plaintext)
            .map_err(|err| format!("reaction emoji is not utf8: {err}"))?;
        grouped
            .entry(row.target_message_id)
            .or_default()
            .push(ReactionDisplayRow {
                created_at_ms: row.created_at_ms,
                reaction_id: row.reaction_id,
                author_user_id: row.author_user_id,
                emoji,
            });
    }
    for rows in grouped.values_mut() {
        rows.sort_by(|left, right| {
            left.created_at_ms
                .cmp(&right.created_at_ms)
                .then_with(|| left.reaction_id.cmp(&right.reaction_id))
        });
    }
    Ok(grouped)
}

fn files_by_message(
    store: &Store,
    workspace_id: FactId,
) -> Result<BTreeMap<FactId, Vec<FileDisplayRow>>, String> {
    let mut grouped: BTreeMap<FactId, Vec<FileDisplayRow>> = BTreeMap::new();
    for row in visible_files(store, workspace_id)? {
        grouped.entry(row.message_id).or_default().push(row);
    }
    Ok(grouped)
}

fn visible_files(store: &Store, workspace_id: FactId) -> Result<Vec<FileDisplayRow>, String> {
    let mut rows = file::queries::content_file_rows(store, workspace_id)?
        .into_iter()
        .map(|row| {
            if !message_is_visible(store, workspace_id, row.message_id)? {
                return Ok(None);
            }
            let message = queries::content_message_row(store, workspace_id, row.message_id)?
                .ok_or_else(|| "file parent message is not visible".to_string())?;
            let key = local_content_key(store, workspace_id, message.frontier_id, message.minute)?;
            let nonce = deterministic_nonce_for_parts(
                b"topo:file-metadata-nonce:v1",
                &[&workspace_id, &row.file_id],
            );
            let metadata = decode_file_metadata(&open_bytes(
                &key,
                &nonce,
                &row.sealed_metadata,
                "file metadata",
            )?)?;
            let slices_received = file_slices(store, workspace_id, row.file_id)?.len() as u32;
            Ok(Some(FileDisplayRow {
                file_fact_id: row.file_fact_id,
                file_id: row.file_id,
                message_id: row.message_id,
                created_at_ms: row.created_at_ms,
                filename: metadata.filename,
                blob_bytes: row.blob_bytes,
                total_slices: row.total_slices,
                slices_received,
                root_hash: row.root_hash,
            }))
        })
        .collect::<Result<Vec<_>, String>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        left.created_at_ms
            .cmp(&right.created_at_ms)
            .then_with(|| left.file_fact_id.cmp(&right.file_fact_id))
    });
    Ok(rows)
}

fn message_is_visible(
    store: &Store,
    workspace_id: FactId,
    message_id: FactId,
) -> Result<bool, String> {
    queries::message_exists(store, workspace_id, message_id)
}

fn file_slices(
    store: &Store,
    workspace_id: FactId,
    file_id: FactId,
) -> Result<Vec<file_slice::rows::ContentFileSliceRow>, String> {
    file_slice::rows::file_slice_rows_for_file(store, workspace_id, file_id)
}

fn resolve_file_selector(
    store: &Store,
    workspace_id: FactId,
    selector: &str,
) -> Result<FileDisplayRow, String> {
    let files = visible_files(store, workspace_id)?;
    if let Some(index) = selector.strip_prefix('#') {
        let index = index
            .parse::<usize>()
            .map_err(|_| "file selector must be #N or a file id".to_string())?;
        if index == 0 {
            return Err("file selector index starts at #1".to_string());
        }
        return files
            .get(index - 1)
            .cloned()
            .ok_or_else(|| "file selector is out of range".to_string());
    }
    let file_fact_id = decode_id(selector)?;
    files
        .into_iter()
        .find(|row| row.file_fact_id == file_fact_id || row.file_id == file_fact_id)
        .ok_or_else(|| "file selector did not match a visible file".to_string())
}

struct FileMetadata {
    filename: String,
    _mime: String,
}

fn encode_file_metadata(filename: &str, mime: &str) -> Result<Vec<u8>, String> {
    if filename.is_empty() {
        return Err("filename must not be empty".to_string());
    }
    let filename = filename.as_bytes();
    let mime = mime.as_bytes();
    let filename_len: u16 = filename
        .len()
        .try_into()
        .map_err(|_| "filename is too long".to_string())?;
    let mime_len: u16 = mime
        .len()
        .try_into()
        .map_err(|_| "mime type is too long".to_string())?;
    let mut out = Vec::with_capacity(5 + filename.len() + mime.len());
    out.push(1);
    out.extend_from_slice(&filename_len.to_be_bytes());
    out.extend_from_slice(&mime_len.to_be_bytes());
    out.extend_from_slice(filename);
    out.extend_from_slice(mime);
    Ok(out)
}

fn decode_file_metadata(bytes: &[u8]) -> Result<FileMetadata, String> {
    if bytes.len() < 5 || bytes[0] != 1 {
        return Err("file metadata is malformed".to_string());
    }
    let filename_len = u16::from_be_bytes(bytes[1..3].try_into().unwrap()) as usize;
    let mime_len = u16::from_be_bytes(bytes[3..5].try_into().unwrap()) as usize;
    if bytes.len() != 5 + filename_len + mime_len {
        return Err("file metadata length is malformed".to_string());
    }
    let filename = String::from_utf8(bytes[5..5 + filename_len].to_vec())
        .map_err(|err| format!("filename is not utf8: {err}"))?;
    let mime = String::from_utf8(bytes[5 + filename_len..].to_vec())
        .map_err(|err| format!("mime is not utf8: {err}"))?;
    Ok(FileMetadata {
        filename,
        _mime: mime,
    })
}

fn signing_fields(
    ctx: &CommandContext<'_>,
    workspace_id: FactId,
) -> Result<(FactId, crypto::Ed25519PublicKey, crypto::Ed25519PrivateKey), String> {
    let signing = ctx.local_signing_capability(workspace_id)?;
    if signing.workspace_id != workspace_id {
        return Err("signing capability is not bound to this workspace".to_string());
    }
    Ok((
        signing.signer_id,
        crypto::ed25519_public_key(&signing.private_key),
        signing.private_key,
    ))
}

fn signed_reaction_fact(
    ctx: &CommandContext<'_>,
    workspace_id: FactId,
    created_at_ms: u64,
    mut reaction: reaction::fact::ContentReactionFact,
) -> Result<Fact, String> {
    let (signer_id, signer_public_key, private_key) = signing_fields(ctx, workspace_id)?;
    reaction.signer_id = signer_id;
    reaction.signer_public_key = signer_public_key;
    reaction.signature = [0; crypto::ED25519_SIGNATURE_BYTES];
    let (_, signature) =
        crypto::ed25519_sign_canonical(&private_key, &reaction::layout::signing_bytes(&reaction)?);
    reaction.signature = signature;
    Ok(Fact::new(
        crate::protocol::auth::workspace::scope(workspace_id),
        created_at_ms,
        reaction::layout::encode_fact(&reaction)?,
    ))
}

fn signed_file_fact(
    ctx: &CommandContext<'_>,
    workspace_id: FactId,
    created_at_ms: u64,
    mut file: file::fact::ContentFileFact,
) -> Result<Fact, String> {
    let (signer_id, signer_public_key, private_key) = signing_fields(ctx, workspace_id)?;
    file.signer_id = signer_id;
    file.signer_public_key = signer_public_key;
    file.signature = [0; crypto::ED25519_SIGNATURE_BYTES];
    let (_, signature) =
        crypto::ed25519_sign_canonical(&private_key, &file::layout::signing_bytes(&file)?);
    file.signature = signature;
    Ok(Fact::new(
        crate::protocol::auth::workspace::scope(workspace_id),
        created_at_ms,
        file::layout::encode_fact(&file)?,
    ))
}

fn signed_file_slice_fact(
    ctx: &CommandContext<'_>,
    workspace_id: FactId,
    created_at_ms: u64,
    mut slice: file_slice::fact::ContentFileSliceFact,
) -> Result<Fact, String> {
    let (signer_id, signer_public_key, private_key) = signing_fields(ctx, workspace_id)?;
    slice.signer_id = signer_id;
    slice.signer_public_key = signer_public_key;
    slice.signature = [0; crypto::ED25519_SIGNATURE_BYTES];
    let (_, signature) =
        crypto::ed25519_sign_canonical(&private_key, &file_slice::layout::signing_bytes(&slice)?);
    slice.signature = signature;
    Ok(Fact::new(
        crate::protocol::auth::workspace::scope(workspace_id),
        created_at_ms,
        file_slice::layout::encode_fact(&slice)?,
    ))
}

struct EncryptedFileSlice {
    created_at_ms: u64,
    slice_index: u32,
    ciphertext: Vec<u8>,
}

fn encrypted_file_slices(
    payload: &[u8],
    key: &XChaCha20Poly1305Key,
    workspace_id: FactId,
    message_id: FactId,
    file_created_at_ms: u64,
) -> Result<Vec<EncryptedFileSlice>, String> {
    let mut slices = Vec::new();
    for (slice_index, chunk) in payload
        .chunks(file_slice::fact::FILE_SLICE_PLAINTEXT_BYTES)
        .enumerate()
    {
        let slice_index = slice_index as u32;
        let nonce = file_slice_nonce(workspace_id, message_id, file_created_at_ms, slice_index);
        slices.push(EncryptedFileSlice {
            created_at_ms: file_created_at_ms.saturating_add(1 + u64::from(slice_index)),
            slice_index,
            ciphertext: seal_bytes(key, &nonce, chunk, "file slice")?,
        });
    }
    Ok(slices)
}

fn encrypted_blob_root_hash(slices: &[EncryptedFileSlice]) -> [u8; 32] {
    let len = slices.iter().map(|slice| slice.ciphertext.len()).sum();
    let mut encrypted_blob = Vec::with_capacity(len);
    for slice in slices {
        encrypted_blob.extend_from_slice(&slice.ciphertext);
    }
    crypto::hash(&encrypted_blob)
}

fn seal_bytes(
    key: &XChaCha20Poly1305Key,
    nonce: &XChaCha20Poly1305Nonce,
    plaintext: &[u8],
    label: &str,
) -> Result<Vec<u8>, String> {
    crypto::xchacha20poly1305_encrypt(key, b"", nonce, plaintext)
        .map_err(|err| format!("{label} encryption failed: {err}"))
}

fn open_bytes(
    key: &XChaCha20Poly1305Key,
    nonce: &XChaCha20Poly1305Nonce,
    ciphertext: &[u8],
    label: &str,
) -> Result<Vec<u8>, String> {
    crypto::xchacha20poly1305_decrypt(key, b"", nonce, ciphertext)
        .map_err(|err| format!("{label} decryption failed: {err}"))
}

fn local_content_key(
    store: &Store,
    workspace_id: FactId,
    frontier_id: FactId,
    minute: u64,
) -> Result<XChaCha20Poly1305Key, String> {
    let facts = persisted_facts(store)?;
    for fact in &facts {
        if let Ok(secret) = auth::local_key_secret::layout::decode_local_key_secret(fact.body()) {
            if secret.workspace_id == workspace_id && secret.frontier_id == frontier_id {
                return Ok(secret.key_secret);
            }
        }
    }
    for fact in facts {
        if let Ok(secret) =
            auth::local_history_node_secret::layout::decode_local_history_node_secret(fact.body())
        {
            let end_minute = secret
                .range_start
                .saturating_add(secret.range_width.saturating_sub(1));
            if secret.workspace_id == workspace_id
                && secret.frontier_id == frontier_id
                && minute >= secret.range_start
                && minute <= end_minute
            {
                return Ok(secret.node_secret);
            }
        }
    }
    Err("no local content key covers encrypted content".to_string())
}

fn file_id_for(
    workspace_id: FactId,
    message_id: FactId,
    created_at_ms: u64,
    filename: &str,
    root_hash: &[u8; 32],
) -> FactId {
    let mut input = Vec::with_capacity(32 + 32 + 8 + filename.len() + 32);
    input.extend_from_slice(&workspace_id);
    input.extend_from_slice(&message_id);
    input.extend_from_slice(&created_at_ms.to_be_bytes());
    input.extend_from_slice(filename.as_bytes());
    input.extend_from_slice(root_hash);
    crypto::hash(&input)
}

fn file_slice_nonce(
    workspace_id: FactId,
    message_id: FactId,
    file_created_at_ms: u64,
    slice_index: u32,
) -> XChaCha20Poly1305Nonce {
    deterministic_nonce_for_parts(
        b"topo:file-slice-nonce:v2",
        &[
            &workspace_id,
            &message_id,
            &file_created_at_ms.to_be_bytes(),
            &slice_index.to_be_bytes(),
        ],
    )
}

fn deterministic_nonce(
    domain: &[u8],
    workspace_id: FactId,
    created_at_ms: u64,
) -> [u8; reaction::fact::REACTION_NONCE_BYTES] {
    let mut input = Vec::with_capacity(domain.len() + 32 + 8);
    input.extend_from_slice(domain);
    input.extend_from_slice(&workspace_id);
    input.extend_from_slice(&created_at_ms.to_be_bytes());
    let hash = crypto::hash(&input);
    let mut nonce = [0; reaction::fact::REACTION_NONCE_BYTES];
    nonce.copy_from_slice(&hash[..reaction::fact::REACTION_NONCE_BYTES]);
    nonce
}

fn deterministic_nonce_for_parts(domain: &[u8], parts: &[&[u8]]) -> XChaCha20Poly1305Nonce {
    let mut input =
        Vec::with_capacity(domain.len() + parts.iter().map(|part| part.len()).sum::<usize>());
    input.extend_from_slice(domain);
    for part in parts {
        input.extend_from_slice(part);
    }
    let hash = crypto::hash(&input);
    let mut nonce = [0; crypto::XCHACHA20_POLY1305_NONCE_BYTES];
    nonce.copy_from_slice(&hash[..crypto::XCHACHA20_POLY1305_NONCE_BYTES]);
    nonce
}

fn format_bytes(bytes: u64) -> String {
    if bytes == 1 {
        "1 B".to_string()
    } else {
        format!("{bytes} B")
    }
}

fn decode_id(value: &str) -> Result<[u8; 32], String> {
    decode_hex_32(value).map_err(|_| "id must be 64 hex characters".to_string())
}

fn short_hex(bytes: &[u8; 32]) -> String {
    encode_hex_32(bytes)[..12].to_string()
}
