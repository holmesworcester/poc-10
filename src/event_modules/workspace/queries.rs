use rusqlite::{Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

use crate::crypto::event_id_from_base64;
use crate::event_modules::{message, peer_shared, reaction, user};
use crate::service::open_db;

/// Look up the workspace_id for the workspace the given peer joined.
///
/// Used by legacy CLI-side bootstrapping to find a peer's workspace; the
/// substrate kernel always names workspace_id directly.
pub fn resolve_workspace_for_peer(
    db: &Connection,
    _peer_id: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let ws_b64: String = db
        .query_row(
            "SELECT workspace_id
             FROM invites_accepted
             ORDER BY created_at ASC, event_id ASC
             LIMIT 1",
            [],
            |row| row.get(0),
        )
        .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
            "no workspace found".into()
        })?;
    event_id_from_base64(&ws_b64)
        .ok_or_else(|| format!("invalid workspace_id in invites_accepted: {}", ws_b64).into())
}

pub struct WorkspaceRow {
    pub event_id: String,
    pub workspace_id: String,
    pub name: String,
}

/// List the workspace row for a single workspace_id.
pub fn list(db: &Connection, workspace_id: &str) -> Result<Vec<WorkspaceRow>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT event_id, workspace_id, COALESCE(name, '')
         FROM workspaces
         WHERE workspace_id = ?1
         ORDER BY event_id",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![workspace_id], |row| {
            Ok(WorkspaceRow {
                event_id: row.get(0)?,
                workspace_id: row.get(1)?,
                name: row.get(2)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Return the workspace display name for the given workspace_id, or empty string.
pub fn name(db: &Connection, workspace_id: &str) -> Result<String, rusqlite::Error> {
    Ok(db
        .query_row(
            "SELECT COALESCE(name, '')
             FROM workspaces
             WHERE workspace_id = ?1
             LIMIT 1",
            rusqlite::params![workspace_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?
        .unwrap_or_default())
}

// ---------------------------------------------------------------------------
// Response types & high-level query functions
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct WorkspaceItem {
    pub event_id: String,
    pub workspace_id: String,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ViewTenant {
    pub event_id: String,
    pub peer_id: String,
    pub username: String,
    pub workspace_id: String,
    pub workspace_name: String,
    pub active: bool,
    pub ready: bool,
}

/// List workspace items for a single workspace_id.
pub fn list_items(
    db: &Connection,
    workspace_id: &str,
) -> Result<Vec<WorkspaceItem>, rusqlite::Error> {
    let rows = list(db, workspace_id)?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let name = if row.name.is_empty() {
                row.workspace_id.clone()
            } else {
                row.name
            };
            WorkspaceItem {
                event_id: row.event_id,
                workspace_id: row.workspace_id,
                name,
            }
        })
        .collect())
}

pub fn list_all_items(db: &Connection) -> Result<Vec<WorkspaceItem>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT MIN(event_id) AS event_id, workspace_id, COALESCE(MAX(name), '')
         FROM workspaces
         GROUP BY workspace_id
         ORDER BY MIN(event_id)",
    )?;
    let rows = stmt.query_map([], |row| {
        let workspace_id: String = row.get(1)?;
        let name: String = row.get(2)?;
        Ok(WorkspaceItem {
            event_id: row.get(0)?,
            workspace_id: workspace_id.clone(),
            name: if name.is_empty() { workspace_id } else { name },
        })
    })?;
    rows.collect::<Result<Vec<_>, _>>()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusResponse {
    pub events_count: i64,
    pub messages_count: i64,
    pub reactions_count: i64,
    pub recorded_events_count: i64,
    pub shared_event_index_count: i64,
    pub tenants: Vec<ViewTenant>,
}

/// Query workspace status counts for a given workspace_id.
pub fn status(db: &Connection, workspace_id: &str) -> StatusResponse {
    let events_count: i64 = db
        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))
        .unwrap_or(0);
    let messages_count = message::count(db, workspace_id).unwrap_or(0);
    let reactions_count = reaction::count(db, workspace_id).unwrap_or(0);
    let shared_event_index_count: i64 = db
        .query_row("SELECT COUNT(*) FROM shared_event_index", [], |row| {
            row.get(0)
        })
        .unwrap_or(0);
    // recorded_events is keyed by `peer_id` which is now meaningless under
    // the workspace_id model — the cross-workspace count is reported as 0
    // in this view; substrate health uses `events_canonical` directly.
    let recorded_events_count: i64 = 0;
    let tenants = list_tenants_for_display(db, workspace_id).unwrap_or_default();

    StatusResponse {
        events_count,
        messages_count,
        reactions_count,
        recorded_events_count,
        shared_event_index_count,
        tenants,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeysResponse {
    pub user_count: i64,
    pub peer_count: i64,
    pub admin_count: i64,
    pub users: Vec<String>,
    pub peers: Vec<String>,
    pub admins: Vec<String>,
}

/// Query key counts and optionally list event IDs.
pub fn keys(
    db: &Connection,
    workspace_id: &str,
    summary: bool,
) -> Result<KeysResponse, rusqlite::Error> {
    let user_count = user::count(db, workspace_id).unwrap_or(0);
    let peer_count = peer_shared::count(db, workspace_id).unwrap_or(0);
    let admin_count = 0;
    let mut users = Vec::new();
    let mut peers = Vec::new();
    let admins: Vec<String> = Vec::new();

    if !summary {
        users = user::list(db, workspace_id)?
            .into_iter()
            .map(|row| row.event_id)
            .collect();
        peers = peer_shared::list_event_ids(db, workspace_id)?;
    }

    Ok(KeysResponse {
        user_count,
        peer_count,
        admin_count,
        users,
        peers,
        admins,
    })
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ContentKeysResponse {
    pub key_secret_count: i64,
    pub latest_key_event_id: Option<String>,
    pub keys: Vec<String>,
}

pub fn content_keys(
    db: &Connection,
    workspace_id: &str,
    summary: bool,
) -> Result<ContentKeysResponse, rusqlite::Error> {
    let key_secret_count: i64 = db.query_row(
        "SELECT COUNT(*) FROM key_secrets WHERE workspace_id = ?1",
        rusqlite::params![workspace_id],
        |row| row.get(0),
    )?;

    let mut stmt = db.prepare(
        "SELECT ks.event_id
         FROM key_secrets ks
         JOIN events e ON e.event_id = ks.event_id
         WHERE ks.workspace_id = ?1
         ORDER BY e.created_at DESC, ks.event_id DESC",
    )?;
    let keys = stmt
        .query_map(rusqlite::params![workspace_id], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    let latest_key_event_id = keys.first().cloned();

    Ok(ContentKeysResponse {
        key_secret_count,
        latest_key_event_id,
        keys: if summary { Vec::new() } else { keys },
    })
}

// ---------------------------------------------------------------------------
// View types and functions
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct ViewReaction {
    pub emoji: String,
    pub reactor_name: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ViewFileSummary {
    pub filename: String,
    pub mime_type: String,
    pub blob_bytes: i64,
    pub total_slices: i64,
    pub slices_received: i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ViewMessage {
    pub id: String,
    pub author_id: String,
    pub author_name: String,
    pub content: String,
    pub created_at: i64,
    pub reactions: Vec<ViewReaction>,
    pub files: Vec<ViewFileSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_op_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ViewUser {
    pub event_id: String,
    pub peer_event_id: String,
    pub username: String,
    pub device_name: String,
}

fn list_view_users(db: &Connection, workspace_id: &str) -> Result<Vec<ViewUser>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT COALESCE(ps.user_event_id, ''),
                ps.event_id,
                COALESCE(u.username, ''),
                COALESCE(ps.device_name, '')
         FROM peers_shared ps
         LEFT JOIN users u ON ps.user_event_id = u.event_id
         WHERE ps.workspace_id = ?1
         ORDER BY LOWER(COALESCE(u.username, '')),
                  LOWER(COALESCE(ps.device_name, '')),
                  ps.event_id",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![workspace_id], |row| {
            Ok(ViewUser {
                event_id: row.get(0)?,
                peer_event_id: row.get(1)?,
                username: row.get(2)?,
                device_name: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// List one ViewTenant entry per hosted workspace. The "active" flag marks
/// the workspace whose id matches `active_workspace_id` (base64).
pub fn list_tenants_for_display(
    db: &Connection,
    active_workspace_id: &str,
) -> Result<Vec<ViewTenant>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT MIN(event_id) AS event_id, workspace_id, COALESCE(MAX(name), '')
         FROM workspaces
         GROUP BY workspace_id
         ORDER BY MIN(event_id)",
    )?;
    let rows = stmt
        .query_map([], |row| {
            let event_id: String = row.get(0)?;
            let workspace_id: String = row.get(1)?;
            let name: String = row.get(2)?;
            Ok((event_id, workspace_id, name))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut tenants = Vec::new();
    for (event_id, workspace_id_b64, workspace_name) in rows {
        // Pick a representative local user (first peer in workspace with
        // matching local_transport_creds) to display as the operator
        // identity for this workspace.
        let username: String = db
            .query_row(
                "SELECT COALESCE(u.username, '')
                 FROM peers_shared ps
                 JOIN local_transport_creds c
                   ON c.peer_id = lower(hex(ps.transport_fingerprint))
                 LEFT JOIN users u ON ps.user_event_id = u.event_id
                 WHERE ps.workspace_id = ?1
                 ORDER BY ps.event_id ASC
                 LIMIT 1",
                rusqlite::params![&workspace_id_b64],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .unwrap_or_default();
        let display_name = if workspace_name.is_empty() {
            workspace_id_b64.clone()
        } else {
            workspace_name
        };
        tenants.push(ViewTenant {
            event_id,
            peer_id: workspace_id_b64.clone(),
            username,
            workspace_id: workspace_id_b64.clone(),
            workspace_name: display_name,
            active: workspace_id_b64 == active_workspace_id,
            ready: true,
        });
    }
    tenants.sort_by(|a, b| {
        b.active
            .cmp(&a.active)
            .then_with(|| a.workspace_name.cmp(&b.workspace_name))
            .then_with(|| a.username.cmp(&b.username))
            .then_with(|| a.event_id.cmp(&b.event_id))
    });
    Ok(tenants)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ViewResponse {
    pub workspace_name: String,
    pub users: Vec<ViewUser>,
    #[serde(alias = "accounts")]
    pub tenants: Vec<ViewTenant>,
    pub own_user_event_id: String,
    pub messages: Vec<ViewMessage>,
}

/// Build the combined view for the given workspace_id (base64).
pub fn view(
    db: &Connection,
    workspace_id: &str,
    limit: usize,
) -> Result<ViewResponse, Box<dyn std::error::Error + Send + Sync>> {
    let workspace_name = name(db, workspace_id).unwrap_or_default();
    let users = list_view_users(db, workspace_id)?;

    let own_user_eid: String =
        if let Some((signer_eid, _)) = peer_shared::load_local_peer_signer(db, workspace_id)? {
            peer_shared::resolve_user_event_id(db, workspace_id, &signer_eid)
                .map(|eid| crate::crypto::event_id_to_base64(&eid))
                .unwrap_or_default()
        } else {
            String::new()
        };

    let tenants = list_tenants_for_display(db, workspace_id)?;

    let msg_resp = message::list(db, workspace_id, limit)?;

    let view_messages: Vec<ViewMessage> = msg_resp
        .messages
        .into_iter()
        .map(|msg| ViewMessage {
            id: msg.id_b64,
            author_id: msg.author_id,
            author_name: msg.author_name,
            content: msg.content,
            created_at: msg.created_at,
            reactions: msg
                .reactions
                .into_iter()
                .map(|r| ViewReaction {
                    emoji: r.emoji,
                    reactor_name: r.reactor_name,
                })
                .collect(),
            files: Vec::new(),
            client_op_id: msg.client_op_id,
        })
        .collect();

    Ok(ViewResponse {
        workspace_name,
        users,
        tenants,
        own_user_event_id: own_user_eid,
        messages: view_messages,
    })
}

/// Build a full workspace view for a given workspace_id (base64).
pub fn view_for_workspace(
    db_path: &str,
    workspace_id: &str,
    limit: usize,
) -> Result<ViewResponse, Box<dyn std::error::Error + Send + Sync>> {
    let db = open_db(db_path)?;
    view(&db, workspace_id, limit)
}
