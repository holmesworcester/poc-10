use std::thread;
use std::time::Duration;
use std::time::Instant;

use crate::crypto::EventId;
use crate::projection::create::create_encrypted_event_synchronous;
use crate::service::open_db_for_peer;
use crate::state::db::queue::current_timestamp_ms_u64;
use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use super::super::message_deletion::MessageDeletionEvent;
use super::super::workspace;
use super::super::ParsedEvent;
use super::codec::MessageEvent;

fn generate_progress_logging_enabled() -> bool {
    std::env::var_os("TOPO_GENERATE_PROGRESS_LOG").is_some()
}

const DEFAULT_GENERATE_HISTORY_SPAN_MS: u64 = 3 * 365 * 24 * 60 * 60 * 1000;

fn parse_history_span_ms(spec: &str) -> Option<u64> {
    let trimmed = spec.trim().to_ascii_lowercase();
    if trimmed.is_empty() {
        return None;
    }
    let (number, unit_ms) = if let Some(value) = trimmed.strip_suffix("ms") {
        (value, 1u64)
    } else if let Some(value) = trimmed.strip_suffix("min") {
        (value, 60_000u64)
    } else if let Some(value) = trimmed.strip_suffix("mo") {
        (value, 30 * 24 * 60 * 60 * 1000u64)
    } else if let Some(value) = trimmed.strip_suffix('s') {
        (value, 1_000u64)
    } else if let Some(value) = trimmed.strip_suffix('m') {
        (value, 60_000u64)
    } else if let Some(value) = trimmed.strip_suffix('h') {
        (value, 60 * 60 * 1000u64)
    } else if let Some(value) = trimmed.strip_suffix('d') {
        (value, 24 * 60 * 60 * 1000u64)
    } else if let Some(value) = trimmed.strip_suffix('w') {
        (value, 7 * 24 * 60 * 60 * 1000u64)
    } else if let Some(value) = trimmed.strip_suffix('y') {
        (value, 365 * 24 * 60 * 60 * 1000u64)
    } else {
        (trimmed.as_str(), 1u64)
    };
    number
        .parse::<u64>()
        .ok()
        .map(|count| count.saturating_mul(unit_ms))
}

fn generate_message_spread_ms() -> Option<u64> {
    std::env::var("TOPO_GENERATE_MESSAGE_SPREAD_MS")
        .ok()
        .and_then(|value| parse_history_span_ms(&value).or_else(|| value.parse::<u64>().ok()))
        .filter(|value| *value > 0)
}

fn resolve_generate_history_span_ms(history_span: Option<&str>) -> u64 {
    history_span
        .and_then(parse_history_span_ms)
        .or_else(generate_message_spread_ms)
        .unwrap_or(DEFAULT_GENERATE_HISTORY_SPAN_MS)
}

fn begin_immediate_with_retry(
    db: &Connection,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    const MAX_ATTEMPTS: usize = 8;
    let log_progress = generate_progress_logging_enabled();
    let retry_start = Instant::now();

    for attempt in 0..MAX_ATTEMPTS {
        match db.execute("BEGIN IMMEDIATE", []) {
            Ok(_) => return Ok(()),
            Err(err) => {
                let msg = err.to_string();
                let is_busy = msg.contains("database is locked") || msg.contains("SQLITE_BUSY");
                if is_busy && attempt + 1 < MAX_ATTEMPTS {
                    let backoff_ms = 25u64 << attempt;
                    if log_progress {
                        eprintln!(
                            "[generate] BEGIN IMMEDIATE busy attempt={} elapsed_ms={} backoff_ms={} err={}",
                            attempt + 1,
                            retry_start.elapsed().as_millis(),
                            backoff_ms,
                            msg
                        );
                    }
                    thread::sleep(Duration::from_millis(backoff_ms));
                    continue;
                }
                if log_progress {
                    eprintln!(
                        "[generate] BEGIN IMMEDIATE failed attempts={} elapsed_ms={} err={}",
                        attempt + 1,
                        retry_start.elapsed().as_millis(),
                        msg
                    );
                }
                return Err(err.into());
            }
        }
    }

    Err("BEGIN IMMEDIATE retry exhausted".into())
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DeleteResponse {
    pub event_id: String,
    pub target: String,
}

pub struct CreateMessageCmd {
    pub workspace_id: [u8; 32],
    pub author_id: [u8; 32],
    pub content: String,
}

pub fn create(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    cmd: CreateMessageCmd,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let msg = ParsedEvent::Message(MessageEvent {
        created_at_ms,
        workspace_id: cmd.workspace_id,
        author_id: cmd.author_id,
        content: cmd.content,
        signed_by: *signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let key_event_id = workspace::identity_ops::ensure_content_key_for_peer(db, recorded_by)?;
    let eid = create_encrypted_event_synchronous(
        db,
        recorded_by,
        &key_event_id,
        &msg,
        Some(signing_key),
    )?;
    Ok(eid)
}

/// High-level send command: creates a message event and returns a SendResponse.
pub fn send(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    workspace_id: [u8; 32],
    author_id: [u8; 32],
    content: &str,
) -> Result<super::SendResponse, String> {
    let eid = create(
        db,
        recorded_by,
        signer_eid,
        signing_key,
        created_at_ms,
        CreateMessageCmd {
            workspace_id,
            author_id,
            content: content.to_string(),
        },
    )
    .map_err(|e| format!("{}", e))?;

    Ok(super::SendResponse {
        content: content.to_string(),
        event_id: hex::encode(eid),
    })
}

// ---------------------------------------------------------------------------
// Message deletion commands (moved from message_deletion/commands.rs)
// ---------------------------------------------------------------------------

pub struct CreateMessageDeletionCmd {
    pub workspace_id: [u8; 32],
    pub target_event_id: [u8; 32],
    pub author_id: [u8; 32],
}

pub fn create_deletion(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    cmd: CreateMessageDeletionCmd,
) -> Result<EventId, Box<dyn std::error::Error + Send + Sync>> {
    let del = ParsedEvent::MessageDeletion(MessageDeletionEvent {
        created_at_ms,
        workspace_id: cmd.workspace_id,
        target_event_id: cmd.target_event_id,
        author_id: cmd.author_id,
        signed_by: *signer_eid,
        signer_type: 5,
        signature: [0u8; 64],
    });
    let key_event_id = workspace::identity_ops::ensure_content_key_for_peer(db, recorded_by)?;
    let eid = create_encrypted_event_synchronous(
        db,
        recorded_by,
        &key_event_id,
        &del,
        Some(signing_key),
    )?;
    Ok(eid)
}

/// High-level delete command: creates a message_deletion event and returns (event_id_hex, target_hex).
pub fn delete_message(
    db: &Connection,
    recorded_by: &str,
    signer_eid: &EventId,
    signing_key: &SigningKey,
    created_at_ms: u64,
    workspace_id: [u8; 32],
    author_id: [u8; 32],
    target_event_id: [u8; 32],
) -> Result<(String, String), String> {
    let event_id = create_deletion(
        db,
        recorded_by,
        signer_eid,
        signing_key,
        created_at_ms,
        CreateMessageDeletionCmd {
            workspace_id,
            target_event_id,
            author_id,
        },
    )
    .map_err(|e| format!("{}", e))?;

    Ok((hex::encode(event_id), hex::encode(target_event_id)))
}

// ---------------------------------------------------------------------------
// Peer-level command wrappers (moved from service.rs)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct GenerateResponse {
    pub count: usize,
}

/// Send a message as a specific peer (daemon provides the peer_id).
pub fn send_for_peer(
    db_path: &str,
    peer_id: &str,
    content: &str,
) -> Result<super::SendResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (recorded_by, db) = open_db_for_peer(db_path, peer_id)?;
    let ctx = workspace::load_local_authoring_context(&db, &recorded_by)?;

    send(
        &db,
        &recorded_by,
        &ctx.signer_event_id,
        &ctx.signing_key,
        current_timestamp_ms_u64(),
        ctx.workspace_id,
        ctx.author_id,
        content,
    )
    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })
}

/// Delete a message as a specific peer.
pub fn delete_message_for_peer(
    db_path: &str,
    peer_id: &str,
    target_hex: &str,
) -> Result<DeleteResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (recorded_by, db) = open_db_for_peer(db_path, peer_id)?;
    let ctx = workspace::load_local_authoring_context(&db, &recorded_by)?;
    let target_event_id = super::resolve(&db, &recorded_by, target_hex)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

    let (event_id, target) = delete_message(
        &db,
        &recorded_by,
        &ctx.signer_event_id,
        &ctx.signing_key,
        current_timestamp_ms_u64(),
        ctx.workspace_id,
        ctx.author_id,
        target_event_id,
    )
    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

    Ok(DeleteResponse { event_id, target })
}

/// Generate N test messages as a specific peer.
pub fn generate_for_peer(
    db_path: &str,
    peer_id: &str,
    count: usize,
    history_span: Option<&str>,
) -> Result<GenerateResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (recorded_by, db) = open_db_for_peer(db_path, peer_id)?;
    let log_progress = generate_progress_logging_enabled();
    let generate_start = Instant::now();
    let ctx = workspace::load_local_authoring_context(&db, &recorded_by)?;
    let spread_ms = Some(resolve_generate_history_span_ms(history_span));
    let end_at_ms = current_timestamp_ms_u64();
    let start_at_ms = spread_ms.map(|spread| end_at_ms.saturating_sub(spread));
    let timestamp_for_index = |index: usize| -> u64 {
        match (start_at_ms, spread_ms, count) {
            (Some(start_at_ms), Some(spread_ms), count) if count > 1 => {
                let numerator = (index as u128).saturating_mul(spread_ms as u128);
                let step = numerator / u128::try_from(count - 1).unwrap_or(1);
                start_at_ms.saturating_add(u64::try_from(step).unwrap_or(u64::MAX))
            }
            (Some(start_at_ms), _, _) => start_at_ms,
            _ => current_timestamp_ms_u64(),
        }
    };

    // Break into smaller batches to avoid holding the write lock too long.
    // A single long transaction causes SQLITE_BUSY for the sync engine's
    // runtime manager, which treats it as a fatal error.
    const BATCH_SIZE: usize = 1000;
    if log_progress {
        eprintln!(
            "[generate] start kind=messages count={} batch_size={} db={} peer={}",
            count, BATCH_SIZE, db_path, peer_id
        );
    }
    let mut i = 0;
    while i < count {
        let batch_end = (i + BATCH_SIZE).min(count);
        let batch_start = Instant::now();
        begin_immediate_with_retry(&db)?;
        for j in i..batch_end {
            create(
                &db,
                &recorded_by,
                &ctx.signer_event_id,
                &ctx.signing_key,
                timestamp_for_index(j),
                CreateMessageCmd {
                    workspace_id: ctx.workspace_id,
                    author_id: ctx.author_id,
                    content: format!("Message {}", j),
                },
            )
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
                format!("create event error: {}", e).into()
            })?;
        }
        db.execute("COMMIT", [])?;
        i = batch_end;
        if log_progress && (i == count || i % 10_000 == 0 || i == BATCH_SIZE) {
            eprintln!(
                "[generate] progress kind=messages committed={} remaining={} batch_ms={} total_ms={}",
                i,
                count.saturating_sub(i),
                batch_start.elapsed().as_millis(),
                generate_start.elapsed().as_millis()
            );
        }
    }
    if log_progress {
        eprintln!(
            "[generate] done kind=messages count={} total_ms={}",
            count,
            generate_start.elapsed().as_millis()
        );
    }

    Ok(GenerateResponse { count })
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
    }

    #[test]
    fn parse_history_span_supports_human_units() {
        assert_eq!(parse_history_span_ms("1500ms"), Some(1_500));
        assert_eq!(parse_history_span_ms("2h"), Some(2 * 60 * 60 * 1000));
        assert_eq!(parse_history_span_ms("3d"), Some(3 * 24 * 60 * 60 * 1000));
        assert_eq!(
            parse_history_span_ms("3y"),
            Some(DEFAULT_GENERATE_HISTORY_SPAN_MS)
        );
    }

    #[test]
    fn resolve_generate_history_span_defaults_to_three_years() {
        let _guard = env_guard();
        std::env::remove_var("TOPO_GENERATE_MESSAGE_SPREAD_MS");
        assert_eq!(
            resolve_generate_history_span_ms(None),
            DEFAULT_GENERATE_HISTORY_SPAN_MS
        );
    }

    #[test]
    fn resolve_generate_history_span_prefers_explicit_argument_over_env() {
        let _guard = env_guard();
        std::env::set_var("TOPO_GENERATE_MESSAGE_SPREAD_MS", "30d");
        assert_eq!(
            resolve_generate_history_span_ms(Some("7d")),
            7 * 24 * 60 * 60 * 1000
        );
        std::env::remove_var("TOPO_GENERATE_MESSAGE_SPREAD_MS");
    }
}
