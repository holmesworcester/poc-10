use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use rusqlite::OptionalExtension;
use serde::{Deserialize, Serialize};

use crate::crypto::{event_id_from_base64, EventId};
use crate::event_modules::{parse_event, ParsedEvent};

// ---------------------------------------------------------------------------
// Identity helpers
//
// These helpers retain a peer_id-shaped scope ("the workspace's primary
// peer") for legacy authoring paths. The substrate-facing query helpers
// below (count, list_event_ids, list_peers, ...) take a workspace_id
// directly — `recorded_by` retired (poc-9 plan).
// ---------------------------------------------------------------------------

fn decode_signing_key(key_bytes: Vec<u8>) -> Result<SigningKey, String> {
    let key_arr: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| "bad signing key length in peer_secrets".to_string())?;
    Ok(SigningKey::from_bytes(&key_arr))
}

fn has_any_workspace_binding(db: &Connection) -> Result<bool, rusqlite::Error> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM invites_accepted LIMIT 1)",
        [],
        |row| row.get(0),
    )
}

fn load_local_peer_signer_from_recorded_event(
    db: &Connection,
    peer_id: &str,
) -> Result<Option<(EventId, SigningKey)>, Box<dyn std::error::Error + Send + Sync>> {
    let blob: Option<Vec<u8>> = db
        .query_row(
            "SELECT e.blob
             FROM recorded_events re
             JOIN events e ON e.event_id = re.event_id
             WHERE re.peer_id = ?1
               AND e.event_type = 'peer_secret'
             ORDER BY re.recorded_at DESC, re.id DESC
             LIMIT 1",
            rusqlite::params![peer_id],
            |row| row.get(0),
        )
        .optional()?;
    let Some(blob) = blob else {
        return Ok(None);
    };
    match parse_event(&blob)? {
        ParsedEvent::PeerSecret(event) => Ok(Some((
            event.signer_event_id,
            SigningKey::from_bytes(&event.private_key_bytes),
        ))),
        other => {
            Err(format!("expected peer_secret event in recorded fallback, got {other:?}").into())
        }
    }
}

/// Load the local peer signer from peer_secrets.
///
/// `peer_id` is the workspace's primary peer fingerprint (hex). This is the
/// legacy CLI authoring entry point — the substrate kernel never calls it.
pub fn load_local_peer_signer(
    db: &Connection,
    peer_id: &str,
) -> Result<Option<(EventId, SigningKey)>, Box<dyn std::error::Error + Send + Sync>> {
    if let Some((eid_b64, key_bytes)) = db
        .query_row(
            "SELECT signer_event_id, private_key
             FROM peer_secrets
             WHERE peer_id = ?1
             ORDER BY created_at DESC, secret_event_id DESC
             LIMIT 1",
            rusqlite::params![peer_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?)),
        )
        .optional()?
    {
        let signing_key = decode_signing_key(key_bytes)?;
        let eid = event_id_from_base64(&eid_b64)
            .ok_or_else(|| "bad local peer signer event_id".to_string())?;
        return Ok(Some((eid, signing_key)));
    }
    if let Some(signer) = load_local_peer_signer_from_recorded_event(db, peer_id)? {
        return Ok(Some(signer));
    }
    Ok(None)
}

/// Like `load_local_peer_signer` but returns an error if no signer is found.
pub fn load_local_peer_signer_required(
    db: &Connection,
    peer_id: &str,
) -> Result<(EventId, SigningKey), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(signer) = load_local_peer_signer(db, peer_id)? {
        return Ok(signer);
    }

    if has_any_workspace_binding(db)? {
        return Err(
            "workspace has not completed initial sync yet — invite accepted, but the local peer identity is not available yet"
                .into(),
        );
    }

    Err("no identity — run `topo create-workspace` first".into())
}

/// Resolve the user_event_id for a specific signer from the peers_shared table.
pub fn resolve_user_event_id(
    db: &Connection,
    _workspace_id: &str,
    signer_eid: &EventId,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let signer_b64 = crate::crypto::event_id_to_base64(signer_eid);
    let user_eid_b64: String = db
        .query_row(
            "SELECT COALESCE(user_event_id, '') FROM peers_shared WHERE event_id = ?1 LIMIT 1",
            rusqlite::params![&signer_b64],
            |row| row.get(0),
        )
        .unwrap_or_default();
    if !user_eid_b64.is_empty() {
        return event_id_from_base64(&user_eid_b64)
            .ok_or_else(|| "invalid user_event_id in peers_shared".into());
    }

    // Fallback: parse the signer event blob directly.
    let signer_blob: Vec<u8> = db
        .query_row(
            "SELECT blob FROM events WHERE event_id = ?1 LIMIT 1",
            rusqlite::params![&signer_b64],
            |row| row.get(0),
        )
        .map_err(|_| -> Box<dyn std::error::Error + Send + Sync> {
            "no peer_shared entry found for signer — identity chain incomplete".into()
        })?;
    let parsed = crate::event_modules::parse_event(&signer_blob).map_err(
        |e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("failed to parse signer event blob: {}", e).into()
        },
    )?;
    if let crate::event_modules::ParsedEvent::PeerShared(ps) = parsed {
        Ok(ps.user_event_id)
    } else {
        Err("signer event is not peer_shared".into())
    }
}

// ---------------------------------------------------------------------------
// Projection queries (workspace-scoped)
// ---------------------------------------------------------------------------

pub fn count(db: &Connection, workspace_id: &str) -> Result<i64, rusqlite::Error> {
    db.query_row(
        "SELECT COUNT(*) FROM peers_shared WHERE workspace_id = ?1",
        rusqlite::params![workspace_id],
        |row| row.get(0),
    )
}

/// List event_ids for all peer_shared rows in a workspace.
pub fn list_event_ids(db: &Connection, workspace_id: &str) -> Result<Vec<String>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT event_id FROM peers_shared WHERE workspace_id = ?1",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![workspace_id], |row| {
            row.get::<_, String>(0)
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Return the first peer_shared event_id for a workspace, if any.
pub fn first_event_id(
    db: &Connection,
    workspace_id: &str,
) -> Result<Option<String>, rusqlite::Error> {
    use rusqlite::OptionalExtension;
    db.query_row(
        "SELECT event_id FROM peers_shared WHERE workspace_id = ?1 LIMIT 1",
        rusqlite::params![workspace_id],
        |row| row.get::<_, String>(0),
    )
    .optional()
}

/// Resolve a projected peer_shared event_id by transport fingerprint.
pub fn resolve_event_id_by_transport_fingerprint(
    db: &Connection,
    workspace_id: &str,
    transport_fingerprint: &[u8; 32],
) -> Result<Option<String>, rusqlite::Error> {
    db.query_row(
        "SELECT event_id
         FROM peers_shared
         WHERE workspace_id = ?1
           AND transport_fingerprint = ?2
         LIMIT 1",
        rusqlite::params![workspace_id, transport_fingerprint.as_slice()],
        |row| row.get::<_, String>(0),
    )
    .optional()
}

pub struct TenantRow {
    pub event_id: String,
    pub device_name: String,
    pub user_event_id: String,
    pub username: String,
}

/// List peer tenants with joined username from users table.
pub fn list_tenants(
    db: &Connection,
    workspace_id: &str,
) -> Result<Vec<TenantRow>, rusqlite::Error> {
    let mut stmt = db.prepare(
        "SELECT ps.event_id, COALESCE(ps.device_name, ''), COALESCE(ps.user_event_id, ''),
                COALESCE(u.username, '')
         FROM peers_shared ps
         LEFT JOIN users u ON ps.user_event_id = u.event_id
         WHERE ps.workspace_id = ?1",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![workspace_id], |row| {
            Ok(TenantRow {
                event_id: row.get(0)?,
                device_name: row.get(1)?,
                user_event_id: row.get(2)?,
                username: row.get(3)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Response types & high-level query functions
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct TenantItem {
    pub event_id: String,
    pub device_name: String,
    pub user_event_id: String,
    pub username: String,
}

/// List tenant items (response type) from the database.
pub fn list_tenant_items(
    db: &Connection,
    workspace_id: &str,
) -> Result<Vec<TenantItem>, rusqlite::Error> {
    let rows = list_tenants(db, workspace_id)?;
    Ok(rows
        .into_iter()
        .map(|row| TenantItem {
            event_id: row.event_id,
            device_name: row.device_name,
            user_event_id: row.user_event_id,
            username: row.username,
        })
        .collect())
}

// ---------------------------------------------------------------------------
// Peers listing (all known peers with endpoint + local status)
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
pub struct PeerItem {
    pub peer_id: String,
    pub device_name: String,
    pub username: String,
    pub user_event_id: String,
    /// True if this peer has local transport credentials (i.e. is a local tenant).
    pub local: bool,
    /// Most recently observed endpoint address, if any.
    pub endpoint: Option<String>,
}

/// List all known peers in a workspace with local/remote status and last-observed endpoint.
pub fn list_peers(db: &Connection, workspace_id: &str) -> Result<Vec<PeerItem>, rusqlite::Error> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let mut stmt = db.prepare(
        "SELECT
            ps.event_id,
            COALESCE(ps.device_name, ''),
            COALESCE(u.username, ''),
            COALESCE(ps.user_event_id, ''),
            EXISTS(
                SELECT 1 FROM local_transport_creds c
                WHERE c.peer_id = lower(hex(ps.transport_fingerprint))
            ) AS is_local,
            (
                SELECT e.origin_ip || ':' || e.origin_port
                FROM peer_endpoint_observations e
                WHERE e.via_peer_id = lower(hex(ps.transport_fingerprint))
                  AND e.expires_at > ?2
                ORDER BY e.observed_at DESC
                LIMIT 1
            ) AS endpoint
         FROM peers_shared ps
         LEFT JOIN users u
           ON ps.user_event_id = u.event_id
         WHERE ps.workspace_id = ?1
         ORDER BY is_local DESC, ps.event_id",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![workspace_id, now_ms], |row| {
            Ok(PeerItem {
                peer_id: row.get(0)?,
                device_name: row.get(1)?,
                username: row.get(2)?,
                user_event_id: row.get(3)?,
                local: row.get(4)?,
                endpoint: row.get(5)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;
    Ok(rows)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IdentityResponse {
    pub transport_fingerprint: String,
    pub user_event_id: Option<String>,
    pub peer_shared_event_id: Option<String>,
}

/// Get combined identity info for a specific peer (legacy CLI-shaped).
pub fn identity(db: &Connection, peer_id: &str) -> Result<IdentityResponse, rusqlite::Error> {
    use rusqlite::OptionalExtension;

    // Find the peers_shared row whose transport fingerprint matches the
    // given peer_id (legacy hex SPKI fingerprint).
    let own_peer: Option<(String, Option<String>)> = db
        .query_row(
            "SELECT ps.event_id, ps.user_event_id
             FROM peers_shared ps
             JOIN local_transport_creds c
               ON c.peer_id = lower(hex(ps.transport_fingerprint))
              AND c.peer_id = ?1
             LIMIT 1",
            rusqlite::params![peer_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, Option<String>>(1)?)),
        )
        .optional()?;

    let (peer_shared_event_id, user_event_id) = match own_peer {
        Some((ps_eid, u_eid)) => (Some(ps_eid), u_eid),
        None => (None, None),
    };

    Ok(IdentityResponse {
        transport_fingerprint: peer_id.to_string(),
        user_event_id,
        peer_shared_event_id,
    })
}
