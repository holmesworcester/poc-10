//! Service layer: thin shell of DB helpers, utilities, and transport-level
//! orchestration.
//!
//! In the substrate-only daemon this file is intentionally minimal — the
//! event-domain authoring layer that historically lived under
//! `event_modules/{message,reaction,workspace}/commands.rs` was retired
//! along with the legacy `recorded_by`-keyed projection apply path. The
//! daemon's authoring surface is `api::run(Command::*)`; the RPC server
//! preserves method names so older clients fail loudly instead of
//! crashing.

use crate::db::{open_connection, schema::create_tables};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

pub type ServiceResult<T> = Result<T, ServiceError>;

#[derive(Debug)]
pub struct ServiceError(pub String);

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ServiceError {}

impl From<String> for ServiceError {
    fn from(s: String) -> Self {
        ServiceError(s)
    }
}

impl From<&str> for ServiceError {
    fn from(s: &str) -> Self {
        ServiceError(s.to_string())
    }
}

impl From<rusqlite::Error> for ServiceError {
    fn from(e: rusqlite::Error) -> Self {
        ServiceError(e.to_string())
    }
}

impl From<hex::FromHexError> for ServiceError {
    fn from(e: hex::FromHexError) -> Self {
        ServiceError(e.to_string())
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for ServiceError {
    fn from(e: Box<dyn std::error::Error + Send + Sync>) -> Self {
        ServiceError(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// DB initialization helpers
// ---------------------------------------------------------------------------

/// Open the daemon DB and ensure the schema exists.
///
/// poc-9: there is one DB per daemon (no per-peer DBs). Callers that need
/// a workspace_id scope resolve it from the request or from the active
/// tenant; this helper just hands them a connection.
pub fn open_db(
    db_path: &str,
) -> Result<rusqlite::Connection, Box<dyn std::error::Error + Send + Sync>> {
    let conn = open_connection(db_path)?;
    create_tables(&conn)?;
    Ok(conn)
}

// ---------------------------------------------------------------------------
// Re-exports for backward compat
// ---------------------------------------------------------------------------

pub use crate::assert::{parse_predicate, query_field, AssertResponse, Op};
pub use crate::event_modules::message::{MessageItem, MessagesResponse, SendResponse};
pub use crate::event_modules::peer_shared::{IdentityResponse, TenantItem};
pub use crate::event_modules::reaction::ReactionItem;
pub use crate::event_modules::user::UserItem;
pub use crate::event_modules::workspace::{
    ContentKeysResponse, KeysResponse, StatusResponse, ViewMessage, ViewReaction, ViewResponse,
    ViewTenant, WorkspaceItem,
};

// ---------------------------------------------------------------------------
// Socket path helper
// ---------------------------------------------------------------------------

/// Derive the RPC socket path from a DB path.
/// Uses `<db_path>.topo.sock` — same directory as the database file.
pub fn socket_path_for_db(db_path: &str) -> std::path::PathBuf {
    let p = std::path::Path::new(db_path);
    let abs = if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(p)
    };
    abs.with_extension("topo.sock")
}
