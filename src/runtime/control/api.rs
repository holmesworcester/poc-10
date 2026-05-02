//! # Public runtime API surface
//!
//! Caller-facing API for the substrate. The CLI and integration tests use
//! this module exclusively — they do NOT touch `events_canonical`,
//! `local_event_intents`, `parse_event`, `ParsedEvent`, `EventStatus`,
//! `EventScope`, or any other substrate-internal symbol.
//!
//! ## Shape
//!
//! - [`Command`] is the typed user-facing command. Variants describe
//!   what the user wants done; they do NOT carry wire-level details.
//! - [`CommandHandle`] is an opaque token. Callers can poll it with
//!   [`await_completion`].
//! - [`CommandOutcome`] enumerates terminal outcomes in domain language
//!   (`Applied`, `Rejected`, `Blocked`, `TimedOut`).
//! - The read-side functions ([`list_workspaces`], [`list_messages`],
//!   [`endpoint_status`]) return typed structs. No raw SQL is exposed.
//! - [`DbHandle`] is an opaque wrapper around the SQLite connection +
//!   (optionally) the runtime's wake bus. Construct it via
//!   [`DbHandle::open`] (CLI: standalone DB connection) or
//!   [`DbHandle::from_runtime`] (tests / in-process daemons: shares the
//!   runtime's connection + wake bus for instant dispatcher wakes).
//! - [`ApiError`] enumerates domain-shaped failures. SQLite / event-encode
//!   errors are flattened into `ApiError::Internal` so callers don't
//!   pattern-match on substrate internals.
//!
//! ## What this module wraps
//!
//! Internally, this module calls into:
//! - `runtime::control::local_intents` for emit + poll (now `pub(crate)`).
//! - `event_modules` for typed event construction (workspace, message,
//!   invite-accepted).
//! - `state::events_canonical` for terminal-state reads.
//!
//! None of those names appear on the public surface.
//!
//! ## Identity / determinism
//!
//! `Command::CreateWorkspace` and `Command::SendMessage` synthesize an
//! ed25519-style 32-byte tag deterministically derived from the database
//! path + a freshly-sampled wall-clock millisecond. This mirrors the
//! behaviour of the previous in-line CLI logic — the substrate currently
//! treats author / signer ids as opaque blobs, so no real cryptographic
//! identity is required for a single-daemon flow. When a real identity
//! layer lands the synthesis will move into a private helper here; the
//! API surface stays the same.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use rusqlite::Connection;
use tokio::sync::Mutex;

use crate::event_modules::{
    encode_event, ConnectionEvent, InviteAcceptedEvent, MessageEvent, ParsedEvent, WorkspaceEvent,
};
use crate::runtime::control::local_intents::{
    self, EmittedIntent, LocalIntentError, WaitError,
};
use crate::runtime::control_loop::wake_bus::WakeBus;
use crate::runtime::control_loop::ControlLoopHandles;
use crate::state::db::{ensure_infra_schema, open_connection};
use crate::state::events_canonical::{EventScope, EventStatus};

// ---------------------------------------------------------------------------
// Public id types
// ---------------------------------------------------------------------------

/// 32-byte workspace identifier. Opaque blob; canonical form is the
/// BLAKE3 of the originating Workspace event's canonical bytes.
pub type WorkspaceId = [u8; 32];

/// 32-byte event identifier (BLAKE3 of canonical bytes).
pub type EventId = [u8; 32];

/// 32-byte endpoint identifier (daemon's stable tag).
pub type EndpointId = [u8; 32];

// ---------------------------------------------------------------------------
// DbHandle — opaque connection + optional wake bus
// ---------------------------------------------------------------------------

/// Opaque database handle. Wraps the SQLite connection (and, when
/// constructed from a running runtime, its wake bus) so callers don't see
/// any of the underlying types.
pub struct DbHandle {
    inner: DbHandleInner,
    db_path: PathBuf,
}

enum DbHandleInner {
    /// Owned connection; no wake bus available.
    Standalone {
        db: Arc<Mutex<Connection>>,
    },
    /// Borrowed from a running runtime: shared connection + wake bus.
    /// Notifying the wake bus on emit makes the dispatcher pick up the
    /// new ready row immediately (no idle-poll wait).
    Runtime {
        db: Arc<Mutex<Connection>>,
        wakes: Arc<WakeBus>,
    },
}

impl DbHandle {
    /// Open a standalone handle against a database file. Ensures the
    /// substrate schema exists. Does NOT start a runtime.
    pub fn open(db_path: impl AsRef<Path>) -> Result<Self, ApiError> {
        let path: PathBuf = db_path.as_ref().to_path_buf();
        let conn = open_connection(&path).map_err(|e| ApiError::Internal {
            msg: format!("open_connection: {}", e),
        })?;
        ensure_infra_schema(&conn).map_err(|e| ApiError::Internal {
            msg: format!("ensure_infra_schema: {}", e),
        })?;
        Ok(DbHandle {
            inner: DbHandleInner::Standalone {
                db: Arc::new(Mutex::new(conn)),
            },
            db_path: path,
        })
    }

    /// Construct a handle that shares a running runtime's connection and
    /// wake bus. Use this in integration tests that own the runtime.
    pub fn from_runtime(handles: &ControlLoopHandles) -> Self {
        DbHandle {
            inner: DbHandleInner::Runtime {
                db: handles.runtime.db.clone(),
                wakes: handles.wakes.clone(),
            },
            db_path: handles.db_path.clone(),
        }
    }

    fn db(&self) -> &Arc<Mutex<Connection>> {
        match &self.inner {
            DbHandleInner::Standalone { db } => db,
            DbHandleInner::Runtime { db, .. } => db,
        }
    }

    fn wakes(&self) -> Option<&Arc<WakeBus>> {
        match &self.inner {
            DbHandleInner::Standalone { .. } => None,
            DbHandleInner::Runtime { wakes, .. } => Some(wakes),
        }
    }

    /// Database path, used for deterministic id derivation. Internal-use
    /// only; not part of the value contract.
    fn db_path(&self) -> &Path {
        &self.db_path
    }
}

// ---------------------------------------------------------------------------
// Command / handle / outcome
// ---------------------------------------------------------------------------

/// User-facing typed command. Variants are the things callers actually do.
#[derive(Debug, Clone)]
pub enum Command {
    /// Create a fresh workspace with the given display name. The
    /// workspace's underlying public key is derived deterministically;
    /// the CLI does not own real identity yet.
    CreateWorkspace { name: String },

    /// Accept an invite. `invite_blob` is the opaque 96-byte
    /// `(invite_event_id || workspace_id || tenant_event_id)` triple
    /// produced by an invite-link generator. Anything other than 96
    /// bytes is rejected.
    AcceptInvite { invite_blob: Vec<u8> },

    /// Send a message into a workspace. `workspace_id` must reference an
    /// already-applied workspace.
    SendMessage {
        workspace_id: WorkspaceId,
        content: String,
    },

    /// Establish a real two-daemon connection given a base64 invite
    /// blob produced by [`encode_connection_invite`]. The handler
    /// authors a `Connection` event signed by the local ed25519
    /// identity, derives connection secrets and `connection_endpoints`
    /// rows, and sends a bootstrap-wrapped frame to the remote so the
    /// remote projects the same `Connection` event and ends up with
    /// symmetric state. The terminal outcome is the `Applied` status
    /// of the local Connection event.
    EstablishConnection { invite_blob: String },
}

/// Opaque handle returned by [`submit`]. Used only as input to
/// [`await_completion`].
#[derive(Debug, Clone)]
pub struct CommandHandle {
    /// Hidden: the substrate's event id for the row this command emitted.
    event_id: EventId,
}

impl CommandHandle {
    /// Borrow the underlying event id as bytes. Provided so callers can
    /// log or persist a stable handle; the bytes themselves are opaque.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.event_id
    }
}

/// Opaque dependency token surfaced when a command is `Blocked`. Today
/// the substrate exposes the missing event id as raw bytes; the type
/// hides the substrate's name for it.
#[derive(Debug, Clone)]
pub struct DepHandle(#[allow(dead_code)] [u8; 32]);

/// Terminal outcome of a command.
#[derive(Debug, Clone)]
pub enum CommandOutcome {
    /// State has been updated.
    Applied,
    /// Permanently rejected.
    Rejected { reason: String },
    /// Stuck waiting for missing dependencies.
    Blocked { missing_deps: Vec<DepHandle> },
    /// Did not reach a terminal state in the allotted time.
    TimedOut,
}

/// Domain-shaped errors. SQL / SQLite / encode errors are flattened into
/// `Internal` so callers never need to pattern-match on substrate
/// internals.
#[derive(Debug)]
pub enum ApiError {
    /// `SendMessage` referenced a workspace that has not been applied.
    WorkspaceNotFound,
    /// `AcceptInvite` blob was the wrong length / invalid.
    InvalidInvite { reason: String },
    /// Bad input shape (e.g. workspace name exceeds the wire layout).
    InvalidArgument { reason: String },
    /// The timeout expired before the command reached a terminal state.
    Timeout,
    /// Anything else (db, encoding, IO).
    Internal { msg: String },
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::WorkspaceNotFound => write!(f, "workspace not found"),
            ApiError::InvalidInvite { reason } => write!(f, "invalid invite: {}", reason),
            ApiError::InvalidArgument { reason } => write!(f, "invalid argument: {}", reason),
            ApiError::Timeout => write!(f, "command timed out"),
            ApiError::Internal { msg } => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for ApiError {}

impl From<LocalIntentError> for ApiError {
    fn from(e: LocalIntentError) -> Self {
        ApiError::Internal {
            msg: format!("local intent: {}", e),
        }
    }
}

impl From<WaitError> for ApiError {
    fn from(e: WaitError) -> Self {
        match e {
            WaitError::Timeout { .. } => ApiError::Timeout,
            WaitError::Db(err) => ApiError::Internal {
                msg: format!("db: {}", err),
            },
        }
    }
}

impl From<rusqlite::Error> for ApiError {
    fn from(e: rusqlite::Error) -> Self {
        ApiError::Internal {
            msg: format!("db: {}", e),
        }
    }
}

// ---------------------------------------------------------------------------
// submit / await_completion / run
// ---------------------------------------------------------------------------

/// Submit a command. Returns a handle that can be polled with
/// [`await_completion`]. Does NOT block until the command reaches a
/// terminal state — for the convenience-blocking variant see [`run`].
pub async fn submit(db: &DbHandle, cmd: Command) -> Result<CommandHandle, ApiError> {
    if let Command::EstablishConnection { invite_blob } = &cmd {
        return submit_establish_connection(db, invite_blob).await;
    }

    let parsed = build_parsed_event(db, &cmd)?;
    let workspace_scope = command_workspace_scope(db, &cmd)?;
    let kind = command_kind_tag(&cmd);

    let emitted = emit(db, kind, &parsed, workspace_scope).await?;
    Ok(CommandHandle {
        event_id: emitted.event_id,
    })
}

/// Wait for a previously-submitted command to reach a terminal state.
/// Returns `CommandOutcome::TimedOut` if the deadline elapses before the
/// substrate transitions the row to a terminal status.
pub async fn await_completion(
    db: &DbHandle,
    handle: &CommandHandle,
    timeout: Duration,
) -> Result<CommandOutcome, ApiError> {
    match local_intents::wait_for_terminal(db.db(), &handle.event_id, timeout).await {
        Ok(EventStatus::Applied) => Ok(CommandOutcome::Applied),
        Ok(EventStatus::Rejected) => Ok(CommandOutcome::Rejected {
            reason: "rejected".to_string(),
        }),
        // The other EventStatus variants are non-terminal; wait_for_terminal
        // would not surface them here.
        Ok(other) => Ok(CommandOutcome::Rejected {
            reason: format!("unexpected terminal status: {:?}", other),
        }),
        Err(WaitError::Timeout { .. }) => {
            // Translate the substrate's "timed out, last status was X"
            // shape into the public outcome enum. If the row is currently
            // `Blocked`, surface that distinction.
            match read_current_status(db, &handle.event_id).await? {
                Some(EventStatus::Blocked) => Ok(CommandOutcome::Blocked {
                    missing_deps: Vec::new(),
                }),
                _ => Ok(CommandOutcome::TimedOut),
            }
        }
        Err(WaitError::Db(e)) => Err(ApiError::Internal {
            msg: format!("db: {}", e),
        }),
    }
}

/// Convenience: submit + await with a single timeout budget.
pub async fn run(
    db: &DbHandle,
    cmd: Command,
    timeout: Duration,
) -> Result<CommandOutcome, ApiError> {
    let handle = submit(db, cmd).await?;
    await_completion(db, &handle, timeout).await
}

// ---------------------------------------------------------------------------
// Bulk authoring (perf testing)
// ---------------------------------------------------------------------------

/// Bulk-author N `SendMessage` events under one DB lock acquisition.
/// Skips the per-call transaction overhead of [`submit`] so a CLI
/// bench loop is not bottlenecked on SQLite busy-timeout retries
/// while the daemon's dispatcher contends for the write lock.
///
/// Returns one `CommandHandle` per emitted event in order.
pub async fn bulk_send_messages(
    db: &DbHandle,
    workspace_id: WorkspaceId,
    count: usize,
    content_prefix: &str,
) -> Result<Vec<CommandHandle>, ApiError> {
    use crate::event_modules::message::MessageEvent;
    use crate::event_modules::ParsedEvent;

    let mut handles = Vec::with_capacity(count);
    {
        let conn = db.db().lock().await;
        conn.execute("BEGIN IMMEDIATE", []).map_err(|e| ApiError::Internal {
            msg: format!("BEGIN IMMEDIATE: {}", e),
        })?;
        for i in 0..count {
            let content = format!("{}-{}", content_prefix, i);
            // Build a MessageEvent the same way as
            // `build_parsed_event(Command::SendMessage)` so we get
            // identical canonical bytes — content + workspace_id +
            // author_id (the daemon's local endpoint id) + creation
            // time, no other fields.
            let author_id = derive_author_id(db.db_path());
            let signer_id = author_id;
            let parsed = ParsedEvent::Message(MessageEvent {
                created_at_ms: now_ms() as u64,
                workspace_id,
                author_id,
                content,
                signed_by: signer_id,
                signer_type: 5,
                signature: [0u8; 64],
            });
            let emitted = local_intents::emit_local_event(
                &conn,
                "SendMessage",
                &parsed,
                Some(workspace_id),
                EventScope::Durable,
            )
            .map_err(|e| ApiError::Internal {
                msg: format!("emit_local_event: {}", e),
            })?;
            handles.push(CommandHandle {
                event_id: emitted.event_id,
            });
        }
        conn.execute("COMMIT", []).map_err(|e| ApiError::Internal {
            msg: format!("COMMIT: {}", e),
        })?;
    }
    if let Some(wakes) = db.wakes() {
        wakes.notify_local_events();
        wakes.notify_ready();
    }
    Ok(handles)
}

// ---------------------------------------------------------------------------
// Read-side queries
// ---------------------------------------------------------------------------

/// Author of a message (display projection).
#[derive(Debug, Clone)]
pub struct AuthorSummary {
    /// 32-byte opaque author id (base64-encoded in projection storage).
    pub author_id_b64: String,
    /// Display name if known, else empty.
    pub display_name: String,
}

/// One workspace's projection summary.
#[derive(Debug, Clone)]
pub struct WorkspaceSummary {
    pub id: WorkspaceId,
    pub name: String,
    /// Wall-clock millisecond when the workspace's originating event was
    /// admitted. May be 0 if the row pre-dates the field.
    pub created_at_ms: i64,
    pub message_count: i64,
    pub user_count: i64,
}

/// One message's projection summary.
#[derive(Debug, Clone)]
pub struct MessageSummary {
    pub id: EventId,
    pub workspace_id: WorkspaceId,
    pub author: AuthorSummary,
    pub content: String,
    pub created_at_ms: i64,
}

/// Aggregate endpoint state.
#[derive(Debug, Clone)]
pub struct EndpointStatus {
    pub endpoint_id: EndpointId,
    pub workspaces: Vec<WorkspaceSummary>,
    pub events_applied: i64,
    pub events_blocked: i64,
    pub events_pending: i64,
}

/// List all applied workspaces.
pub async fn list_workspaces(db: &DbHandle) -> Result<Vec<WorkspaceSummary>, ApiError> {
    let g = db.db().lock().await;
    list_workspaces_inner(&g)
}

/// Synchronous variant of [`list_workspaces`] for callers that already
/// hold a connection (RPC dispatch, CLI helpers).
pub fn list_workspaces_blocking(
    conn: &Connection,
) -> Result<Vec<WorkspaceSummary>, ApiError> {
    list_workspaces_inner(conn)
}

/// List up to `limit` messages in `workspace`. `limit == 0` means
/// "no limit". Messages are returned in canonical chain order.
pub async fn list_messages(
    db: &DbHandle,
    workspace: WorkspaceId,
    limit: usize,
) -> Result<Vec<MessageSummary>, ApiError> {
    let g = db.db().lock().await;
    list_messages_inner(&g, &workspace, limit)
}

/// Aggregate endpoint status.
pub async fn endpoint_status(db: &DbHandle) -> Result<EndpointStatus, ApiError> {
    let g = db.db().lock().await;
    endpoint_status_inner(&g, db.db_path())
}

// ---------------------------------------------------------------------------
// Internals (private — never re-exported)
// ---------------------------------------------------------------------------

async fn emit(
    db: &DbHandle,
    kind: &'static str,
    event: &ParsedEvent,
    workspace_scope: Option<WorkspaceId>,
) -> Result<EmittedIntent, ApiError> {
    let result = {
        let conn = db.db().lock().await;
        local_intents::emit_local_event(
            &conn,
            kind,
            event,
            workspace_scope,
            EventScope::Durable,
        )?
    };
    if let Some(wakes) = db.wakes() {
        wakes.notify_local_events();
        wakes.notify_ready();
    }
    Ok(result)
}

async fn read_current_status(
    db: &DbHandle,
    event_id: &EventId,
) -> Result<Option<EventStatus>, ApiError> {
    let g = db.db().lock().await;
    let row = crate::state::events_canonical::get(&g, event_id)?;
    Ok(row.map(|r| r.status))
}

fn build_parsed_event(db: &DbHandle, cmd: &Command) -> Result<ParsedEvent, ApiError> {
    match cmd {
        Command::CreateWorkspace { name } => {
            let max = crate::event_modules::layout::common::NAME_BYTES;
            if name.as_bytes().len() > max {
                return Err(ApiError::InvalidArgument {
                    reason: format!(
                        "workspace name too long: {} bytes, max {}",
                        name.as_bytes().len(),
                        max
                    ),
                });
            }
            let pubkey = derive_workspace_pubkey(db.db_path(), name);
            Ok(ParsedEvent::Workspace(WorkspaceEvent {
                created_at_ms: now_ms() as u64,
                workspace_id: pubkey,
                public_key: pubkey,
                name: name.clone(),
            }))
        }

        Command::AcceptInvite { invite_blob } => {
            if invite_blob.len() != 96 {
                return Err(ApiError::InvalidInvite {
                    reason: format!(
                        "invite blob must be exactly 96 bytes (got {})",
                        invite_blob.len()
                    ),
                });
            }
            let mut invite_event_id = [0u8; 32];
            let mut workspace_id = [0u8; 32];
            let mut tenant_event_id = [0u8; 32];
            invite_event_id.copy_from_slice(&invite_blob[0..32]);
            workspace_id.copy_from_slice(&invite_blob[32..64]);
            tenant_event_id.copy_from_slice(&invite_blob[64..96]);
            Ok(ParsedEvent::InviteAccepted(InviteAcceptedEvent {
                created_at_ms: now_ms() as u64,
                tenant_event_id,
                invite_event_id,
                workspace_id,
            }))
        }

        Command::SendMessage {
            workspace_id,
            content,
        } => {
            let author_id = derive_author_id(db.db_path());
            let signer_id = author_id;
            Ok(ParsedEvent::Message(MessageEvent {
                created_at_ms: now_ms() as u64,
                workspace_id: *workspace_id,
                author_id,
                content: content.clone(),
                signed_by: signer_id,
                signer_type: 5,
                signature: [0u8; 64],
            }))
        }
        Command::EstablishConnection { .. } => Err(ApiError::Internal {
            msg: "EstablishConnection has its own submit path".to_string(),
        }),
    }
}

fn command_workspace_scope(
    _db: &DbHandle,
    cmd: &Command,
) -> Result<Option<WorkspaceId>, ApiError> {
    match cmd {
        // Workspace events are self-rooting; the helper lets the
        // workspace_id fall through to the event id.
        Command::CreateWorkspace { .. } => Ok(None),
        Command::AcceptInvite { invite_blob } => {
            if invite_blob.len() != 96 {
                return Err(ApiError::InvalidInvite {
                    reason: format!(
                        "invite blob must be exactly 96 bytes (got {})",
                        invite_blob.len()
                    ),
                });
            }
            let mut workspace_id = [0u8; 32];
            workspace_id.copy_from_slice(&invite_blob[32..64]);
            Ok(Some(workspace_id))
        }
        Command::SendMessage { workspace_id, .. } => Ok(Some(*workspace_id)),
        Command::EstablishConnection { .. } => Ok(None),
    }
}

fn command_kind_tag(cmd: &Command) -> &'static str {
    match cmd {
        Command::CreateWorkspace { .. } => "create_workspace",
        Command::AcceptInvite { .. } => "accept_invite",
        Command::SendMessage { .. } => "send_message",
        Command::EstablishConnection { .. } => "establish_connection",
    }
}

// ---------------------------------------------------------------------------
// Read-side: synchronous SQL queries against the projection tables
// ---------------------------------------------------------------------------

fn list_workspaces_inner(conn: &Connection) -> Result<Vec<WorkspaceSummary>, ApiError> {
    use base64::Engine;
    // workspaces is keyed by (workspace_id, event_id). For the CLI's
    // single-tenant use case, group by workspace_id and pick a stable
    // representative row (MIN(event_id), arbitrary MAX(name)).
    let mut stmt = conn.prepare(
        "SELECT workspace_id, COALESCE(MAX(name), '')
         FROM workspaces
         GROUP BY workspace_id
         ORDER BY MIN(event_id)",
    )?;
    let rows = stmt
        .query_map([], |r| {
            let ws_id_b64: String = r.get(0)?;
            let name: String = r.get(1)?;
            Ok((ws_id_b64, name))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut out = Vec::with_capacity(rows.len());
    for (ws_b64, name) in rows {
        let ws_id = decode_b64_to_id(&ws_b64).map_err(|e| ApiError::Internal {
            msg: format!("decode workspace_id: {}", e),
        })?;

        // created_at_ms: lookup the originating event's row.
        let ws_id_b64 =
            base64::engine::general_purpose::STANDARD.encode(ws_id);
        let created_at_ms: i64 = conn
            .query_row(
                "SELECT created_at_ms FROM events_canonical
                 WHERE event_id = ?1",
                rusqlite::params![ws_id.to_vec()],
                |r| r.get(0),
            )
            .unwrap_or(0);

        let message_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM messages WHERE workspace_id = ?1",
                rusqlite::params![ws_id_b64],
                |r| r.get(0),
            )
            .unwrap_or(0);
        let user_count: i64 = count_users_in_workspace(conn, &ws_id_b64);

        out.push(WorkspaceSummary {
            id: ws_id,
            name,
            created_at_ms,
            message_count,
            user_count,
        });
    }
    Ok(out)
}

fn count_users_in_workspace(conn: &Connection, ws_id_b64: &str) -> i64 {
    // The `users` projection table may or may not exist depending on
    // which event modules have run; use a defensive query.
    conn.query_row(
        "SELECT COUNT(*) FROM users WHERE workspace_id = ?1",
        rusqlite::params![ws_id_b64],
        |r| r.get(0),
    )
    .unwrap_or(0)
}

fn list_messages_inner(
    conn: &Connection,
    workspace: &WorkspaceId,
    limit: usize,
) -> Result<Vec<MessageSummary>, ApiError> {
    use base64::Engine;
    let ws_id_b64 = base64::engine::general_purpose::STANDARD.encode(workspace);

    let sql = if limit > 0 {
        format!(
            "SELECT m.message_id, m.workspace_id, m.author_id, m.content, m.created_at,
                    COALESCE(u.username, '') as author_name
             FROM messages m
             LEFT JOIN users u ON m.author_id = u.event_id
             WHERE m.workspace_id = ?1
             ORDER BY m.created_at ASC, m.message_id ASC
             LIMIT {}",
            limit
        )
    } else {
        "SELECT m.message_id, m.workspace_id, m.author_id, m.content, m.created_at,
                COALESCE(u.username, '') as author_name
         FROM messages m
         LEFT JOIN users u ON m.author_id = u.event_id
         WHERE m.workspace_id = ?1
         ORDER BY m.created_at ASC, m.message_id ASC"
            .to_string()
    };

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt
        .query_map(rusqlite::params![ws_id_b64], |r| {
            let msg_id_b64: String = r.get(0)?;
            let ws_id_b64: String = r.get(1)?;
            let author_id_b64: String = r.get(2)?;
            let content: String = r.get(3)?;
            let created_at: i64 = r.get(4)?;
            let author_name: String = r.get(5)?;
            Ok((msg_id_b64, ws_id_b64, author_id_b64, content, created_at, author_name))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut out = Vec::with_capacity(rows.len());
    for (msg_b64, ws_b64, author_b64, content, created_at, author_name) in rows {
        let msg_id = decode_b64_to_id(&msg_b64).map_err(|e| ApiError::Internal {
            msg: format!("decode message_id: {}", e),
        })?;
        let ws_id = decode_b64_to_id(&ws_b64).map_err(|e| ApiError::Internal {
            msg: format!("decode workspace_id: {}", e),
        })?;
        out.push(MessageSummary {
            id: msg_id,
            workspace_id: ws_id,
            author: AuthorSummary {
                author_id_b64: author_b64,
                display_name: author_name,
            },
            content,
            created_at_ms: created_at,
        });
    }
    Ok(out)
}

fn endpoint_status_inner(
    conn: &Connection,
    db_path: &Path,
) -> Result<EndpointStatus, ApiError> {
    let workspaces = list_workspaces_inner(conn)?;

    // Aggregate event counts. We bucket the substrate's lifecycle into
    // {applied, blocked, pending}: applied is terminal-good, blocked is
    // explicitly waiting, pending covers ready/processing.
    let mut applied: i64 = 0;
    let mut blocked: i64 = 0;
    let mut pending: i64 = 0;
    let mut stmt = conn.prepare(
        "SELECT status, COUNT(*) FROM events_canonical GROUP BY status",
    )?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))?
        .collect::<Result<Vec<_>, _>>()?;
    for (status, count) in rows {
        match status.as_str() {
            "applied" => applied += count,
            "blocked" => blocked += count,
            "ready" | "processing" => pending += count,
            // 'rejected' is terminal-bad; not counted here.
            _ => {}
        }
    }

    Ok(EndpointStatus {
        endpoint_id: derive_endpoint_id(db_path),
        workspaces,
        events_applied: applied,
        events_blocked: blocked,
        events_pending: pending,
    })
}

// ---------------------------------------------------------------------------
// Helpers (deterministic id derivation; matches the prior in-line CLI logic).
// ---------------------------------------------------------------------------

fn derive_workspace_pubkey(db_path: &Path, name: &str) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(db_path.to_string_lossy().as_bytes());
    h.update(b"\x00");
    h.update(name.as_bytes());
    h.update(b"\x00");
    h.update(&now_ms().to_le_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

fn derive_author_id(db_path: &Path) -> [u8; 32] {
    let canonical = std::fs::canonicalize(db_path)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| db_path.to_string_lossy().to_string());
    let mut h = blake3::Hasher::new();
    h.update(b"topo-author:");
    h.update(canonical.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

fn derive_endpoint_id(db_path: &Path) -> [u8; 32] {
    let canonical = std::fs::canonicalize(db_path)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| db_path.to_string_lossy().to_string());
    let mut id = [0u8; 32];
    id.copy_from_slice(blake3::hash(canonical.as_bytes()).as_bytes());
    id
}

fn decode_b64_to_id(s: &str) -> Result<[u8; 32], String> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|e| format!("base64: {}", e))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Two-daemon connection bootstrap
// ---------------------------------------------------------------------------

/// On-disk filename for the per-DB ed25519 signing key.
fn signing_key_path(db_path: &Path) -> PathBuf {
    let mut p = db_path.to_path_buf();
    let stem = p
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "topo.db".to_string());
    p.set_file_name(format!(".{}.signkey", stem));
    p
}

/// Load (or generate) the daemon's persistent ed25519 signing key.
/// The file is 32 raw bytes — the seed of the SigningKey. The verifying
/// key bytes derived from this seed serve as the `endpoint_id`.
pub fn ensure_signing_key(db_path: &Path) -> Result<SigningKey, ApiError> {
    let path = signing_key_path(db_path);
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            return Ok(SigningKey::from_bytes(&seed));
        }
    }
    // Generate fresh.
    use rand::RngCore;
    let mut seed = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut seed);
    let key = SigningKey::from_bytes(&seed);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    std::fs::write(&path, seed).map_err(|e| ApiError::Internal {
        msg: format!("write signing key: {}", e),
    })?;
    Ok(key)
}

/// Encode a base64 invite blob carrying `(endpoint_id, listen_addr,
/// workspace_id)`. Layout:
///
/// ```text
///   [u8;32 endpoint_id]
///   [u8 addr_len][addr_str]   // addr_len <= 64
///   [u8;32 workspace_id]
/// ```
pub fn encode_connection_invite(
    endpoint_id: &EndpointId,
    addr: SocketAddr,
    workspace_id: &WorkspaceId,
) -> String {
    let addr_str = addr.to_string();
    let bytes = addr_str.as_bytes();
    debug_assert!(bytes.len() < 256, "addr too long");
    let mut out = Vec::with_capacity(32 + 1 + bytes.len() + 32);
    out.extend_from_slice(endpoint_id);
    out.push(bytes.len() as u8);
    out.extend_from_slice(bytes);
    out.extend_from_slice(workspace_id);
    base64::engine::general_purpose::STANDARD.encode(out)
}

/// Decode the invite blob. Returns `(endpoint_id, addr, workspace_id)`.
pub fn decode_connection_invite(
    s: &str,
) -> Result<(EndpointId, SocketAddr, WorkspaceId), ApiError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s.trim())
        .map_err(|e| ApiError::InvalidArgument {
            reason: format!("invite base64: {}", e),
        })?;
    if bytes.len() < 32 + 1 + 1 + 32 {
        return Err(ApiError::InvalidArgument {
            reason: format!("invite too short: {} bytes", bytes.len()),
        });
    }
    let mut endpoint_id = [0u8; 32];
    endpoint_id.copy_from_slice(&bytes[0..32]);
    let addr_len = bytes[32] as usize;
    if bytes.len() < 32 + 1 + addr_len + 32 {
        return Err(ApiError::InvalidArgument {
            reason: format!("invite truncated (addr_len {})", addr_len),
        });
    }
    let addr_str = std::str::from_utf8(&bytes[33..33 + addr_len]).map_err(|e| {
        ApiError::InvalidArgument {
            reason: format!("invite addr utf8: {}", e),
        }
    })?;
    let addr = SocketAddr::from_str(addr_str).map_err(|e| ApiError::InvalidArgument {
        reason: format!("invite addr parse: {}", e),
    })?;
    let mut workspace_id = [0u8; 32];
    workspace_id.copy_from_slice(&bytes[33 + addr_len..33 + addr_len + 32]);
    Ok((endpoint_id, addr, workspace_id))
}

/// Build a Connection event signed by `signing_key`. `endpoint_a` and
/// `endpoint_b` are sorted by raw bytes so both sides agree on the
/// canonical id (same sorted endpoints + same signed_at_ms + same
/// shared workspaces + same signer + same signature == same id).
fn build_connection_event(
    signing_key: &SigningKey,
    local_endpoint_id: EndpointId,
    remote_endpoint_id: EndpointId,
    workspace_id: WorkspaceId,
    signed_at_ms: u64,
) -> ConnectionEvent {
    let (endpoint_a, endpoint_b) = if local_endpoint_id <= remote_endpoint_id {
        (local_endpoint_id, remote_endpoint_id)
    } else {
        (remote_endpoint_id, local_endpoint_id)
    };
    let mut shared = std::collections::BTreeSet::new();
    shared.insert(workspace_id);
    let mut ev = ConnectionEvent {
        created_at_ms: signed_at_ms,
        endpoint_a,
        endpoint_b,
        shared_workspaces: shared,
        signed_at_ms,
        signer: signing_key.verifying_key().to_bytes(),
        signature: [0u8; 64],
    };
    let sig = signing_key.sign(&ev.signing_bytes());
    ev.signature = sig.to_bytes();
    ev
}

/// EstablishConnection submit path. Authors a `Connection` event,
/// admits + finalizes it locally so the dispatcher applies it (which
/// lets the projector emit secrets / endpoints / address rows via the
/// post-apply hook), and bootstrap-wraps the canonical bytes to the
/// remote so it sees the same event.
async fn submit_establish_connection(
    db: &DbHandle,
    invite_blob: &str,
) -> Result<CommandHandle, ApiError> {
    let (remote_endpoint_id, remote_addr, workspace_id) = decode_connection_invite(invite_blob)?;
    let signing_key = ensure_signing_key(db.db_path())?;
    let local_endpoint_id = signing_key.verifying_key().to_bytes();
    if local_endpoint_id == remote_endpoint_id {
        return Err(ApiError::InvalidArgument {
            reason: "remote and local endpoints are identical".to_string(),
        });
    }

    let signed_at_ms = now_ms() as u64;
    let event = build_connection_event(
        &signing_key,
        local_endpoint_id,
        remote_endpoint_id,
        workspace_id,
        signed_at_ms,
    );
    let parsed = ParsedEvent::Connection(event.clone());
    let canonical_bytes = encode_event(&parsed).map_err(|e| ApiError::Internal {
        msg: format!("encode connection event: {}", e),
    })?;

    // Pre-record the remote's address so our own outbound sender can
    // dial back as soon as the projector sets up secrets / endpoints.
    {
        let g = db.db().lock().await;
        crate::runtime::transport_v2::upsert_endpoint_address(&g, &remote_endpoint_id, &remote_addr)
            .map_err(|e| ApiError::Internal {
                msg: format!("upsert_endpoint_address: {}", e),
            })?;
    }
    if let Some(ctx) = crate::runtime::control_loop::OutboxWakeContext::current() {
        ctx.address_book.insert(remote_endpoint_id, remote_addr);
    }

    // Emit the local Connection event into the substrate. The Connection
    // projector populates `connections` + `connection_shared_workspaces`,
    // and the post-apply hook (see `event_modules::connection::post_apply`)
    // derives connection_secrets + connection_endpoints rows.
    let emitted = emit(db, "establish_connection", &parsed, None).await?;

    // Send a bootstrap frame carrying the canonical Connection bytes to
    // the remote. This is symmetric: the remote unwraps a bootstrap
    // frame, runs the inbound chain, projects the same Connection event,
    // and ends up with mirror-image state (same connection_id, same
    // secrets, same endpoints rows). We use `wrap_bootstrap_with_addr`
    // directly and dial a fresh TCP connection from the CLI process —
    // we do NOT wait for the local sender actor because the secrets
    // aren't necessarily applied yet.
    //
    // We embed our daemon's listen addr in the bootstrap envelope so
    // the responder can register `endpoint_addresses[local_endpoint] =
    // listen_addr` immediately. Without this the responder would only
    // see the ephemeral source port the CLI used to send the
    // bootstrap, which is closed by the time it tries to dial back.
    let local_listen_addr = read_local_listen_addr_for_db(db.db_path())?;
    send_bootstrap_frame(
        &signing_key,
        remote_endpoint_id,
        remote_addr,
        local_listen_addr,
        workspace_id,
        canonical_bytes,
    )
    .await
    .map_err(|e| ApiError::Internal {
        msg: format!("bootstrap send: {}", e),
    })?;

    Ok(CommandHandle {
        event_id: emitted.event_id,
    })
}

/// Open a fresh TCP connection to `remote_addr` and write a single
/// bootstrap-wrapped frame containing the canonical Connection bytes.
/// The frame embeds `local_listen_addr` so the responder can register
/// our DAEMON listen addr (not the CLI's ephemeral source port) for
/// dial-back.
async fn send_bootstrap_frame(
    local_signing_key: &SigningKey,
    remote_endpoint_id: EndpointId,
    remote_addr: SocketAddr,
    local_listen_addr: SocketAddr,
    workspace_id: WorkspaceId,
    connection_event_bytes: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    use crate::event_modules::connection::wrap::{wrap_bootstrap_with_addr, InnerCanonicalEvent};

    let inner = vec![InnerCanonicalEvent {
        workspace_id,
        bytes: connection_event_bytes,
    }];
    let addr_str = local_listen_addr.to_string();
    let frame = wrap_bootstrap_with_addr(
        local_signing_key,
        remote_endpoint_id,
        &addr_str,
        &inner,
    )?;
    let payload = frame.as_bytes();
    let mut stream = TcpStream::connect(remote_addr).await?;
    let len = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(payload).await?;
    stream.flush().await?;
    // Stay open briefly so the responder can actually read the frame
    // before we close. (TCP won't necessarily flush a half-close before
    // EOF on the read side.)
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    drop(stream);
    Ok(())
}

/// Read the daemon's listen address from the file written by
/// `cmd_start` in `bin/topo/main.rs`. Returns an `ApiError` if the
/// file is missing or unparseable.
fn read_local_listen_addr_for_db(db_path: &Path) -> Result<SocketAddr, ApiError> {
    let mut p = db_path.to_path_buf();
    let stem = p
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "topo.db".to_string());
    p.set_file_name(format!(".{}.listen", stem));
    let s = std::fs::read_to_string(&p).map_err(|e| ApiError::Internal {
        msg: format!("read listen file {}: {}", p.display(), e),
    })?;
    SocketAddr::from_str(s.trim()).map_err(|e| ApiError::Internal {
        msg: format!("parse listen addr: {}", e),
    })
}
