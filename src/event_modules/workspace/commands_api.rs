use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use super::commands::{
    add_device_to_workspace, create_device_link_invite, create_user_invite, create_workspace,
    join_workspace_as_new_user, persist_join_peer_secret, persist_link_peer_secret,
};
use crate::crypto::{event_id_from_base64, event_id_to_base64, EventId};
use crate::service::{open_db_for_peer, open_db_load};

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateWorkspaceResponse {
    pub peer_id: String,
    pub workspace_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateInviteResponse {
    pub invite_link: String,
    pub invite_event_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcceptInviteResponse {
    pub peer_id: String,
    pub user_event_id: String,
    pub peer_shared_event_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AcceptDeviceLinkResponse {
    pub peer_id: String,
    pub peer_shared_event_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RotateKeyResponse {
    pub key_event_id: String,
    pub rotation_event_id: String,
    pub proactive_share_count: usize,
}

// Wave 1: admin event dropped. We treat any peer-signed identity as
// authorized to mint invites; the admin distinction is reintroduced in Wave 2.
fn signer_is_admin(
    db: &Connection,
    recorded_by: &str,
    signer_event_id: &EventId,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let signer_b64 = event_id_to_base64(signer_event_id);
    let exists: bool = db.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM peers_shared
             WHERE recorded_by = ?1 AND event_id = ?2
         )",
        rusqlite::params![recorded_by, signer_b64],
        |row| row.get(0),
    )?;
    Ok(exists)
}

// Wave 1: admin event dropped. Return the user_event_id from peers_shared as
// the stand-in "authority" event id so peer-signed invites still validate.
fn resolve_admin_event_for_signer(
    db: &Connection,
    recorded_by: &str,
    signer_event_id: &EventId,
) -> Result<Option<EventId>, Box<dyn std::error::Error + Send + Sync>> {
    use rusqlite::OptionalExtension;
    let signer_b64 = event_id_to_base64(signer_event_id);
    let user_b64: Option<String> = db
        .query_row(
            "SELECT user_event_id FROM peers_shared
             WHERE recorded_by = ?1 AND event_id = ?2",
            rusqlite::params![recorded_by, signer_b64],
            |row| row.get(0),
        )
        .optional()?;

    match user_b64 {
        Some(v) => {
            let eid = event_id_from_base64(&v)
                .ok_or_else(|| format!("invalid user event_id encoding in DB: {}", v))?;
            Ok(Some(eid))
        }
        None => Ok(None),
    }
}

fn decode_hex32(
    value: &str,
    what: &str,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let bytes = hex::decode(value)?;
    if bytes.len() != 32 {
        return Err(format!("{what} is not valid 32-byte hex SPKI").into());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn resolve_invite_bootstrap_spki(
    db: &Connection,
    public_spki_hex: Option<&str>,
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    if let Some(spki_hex) = public_spki_hex {
        return decode_hex32(spki_hex, "SPKI");
    }

    let (daemon_peer_id, _cert, _key) =
        crate::runtime::legacy_identity::ensure_daemon_identity(db)?;
    decode_hex32(&daemon_peer_id, "daemon_peer_id")
}

// DB-path-level command wrappers (moved from service.rs)

pub fn create_workspace_for_db(
    db_path: &str,
    workspace_name: &str,
    username: &str,
    device_name: &str,
) -> Result<CreateWorkspaceResponse, Box<dyn std::error::Error + Send + Sync>> {
    use crate::db::{open_connection, schema::create_tables};

    let conn = open_connection(db_path)?;
    create_tables(&conn)?;

    // Workspace creation is tenant-agnostic at the control plane: it always
    // mints a fresh local tenant/workspace instead of reusing the active one.
    let result = create_workspace(&conn, "bootstrap", workspace_name, username, device_name)?;

    // Plan.md line 114: at most one workspace instance per daemon endpoint.
    // Sanity-check post-create: the freshly minted workspace_id must not
    // already be bound under another local tenant. This catches
    // collisions and any logic bug that would re-emit a known workspace
    // as new. We probe rather than reject creation up-front because the
    // workspace_id is only known after the create call computes it.
    if let Err(e) =
        super::uniqueness::endpoint_already_hosts_workspace(&conn, &result.workspace_id)
    {
        return Err(format!("workspace uniqueness probe failed: {}", e).into());
    } else {
        // Count the bindings: the create itself emits one InviteAccepted
        // row (the self-accept). More than one means a pre-existing
        // binding existed before this call — plan.md line 114 violation.
        use crate::crypto::event_id_to_base64;
        let ws_b64 = event_id_to_base64(&result.workspace_id);
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM invites_accepted WHERE workspace_id = ?1",
            rusqlite::params![&ws_b64],
            |row| row.get(0),
        )?;
        if n > 1 {
            return Err(super::uniqueness::EndpointWorkspaceUniquenessError {
                workspace_id: result.workspace_id,
                reason: "create_workspace would bind a workspace_id already hosted by this daemon"
                    .to_string(),
            }
            .into());
        }
    }

    let peer_id = hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
        &result.peer_shared_key.verifying_key().to_bytes(),
    ));

    Ok(CreateWorkspaceResponse {
        peer_id,
        workspace_id: event_id_to_base64(&result.workspace_id),
    })
}

/// Create a user invite for the active workspace.
///
/// When `bootstrap_addrs` is empty, auto-detects non-loopback addresses.
fn create_invite_for_recorded_by(
    db: &Connection,
    recorded_by: &str,
    bootstrap_addrs: &[super::invite_link::BootstrapAddress],
    listen_port: u16,
    public_spki_hex: Option<&str>,
) -> Result<CreateInviteResponse, Box<dyn std::error::Error + Send + Sync>> {
    let _ = super::load_local_authoring_context(db, recorded_by)?;
    let ws_eid = super::resolve_workspace_for_peer(db, recorded_by)?;
    let (sender_peer_eid, sender_peer_key) =
        crate::event_modules::peer_shared::load_local_peer_signer_required(db, recorded_by)?;
    if !signer_is_admin(db, recorded_by, &sender_peer_eid)? {
        return Err("Local peer signer is not admin for this workspace.".into());
    }
    let admin_event_id = resolve_admin_event_for_signer(db, recorded_by, &sender_peer_eid)?
        .ok_or_else(|| -> Box<dyn std::error::Error + Send + Sync> {
            "Could not resolve admin event for local peer signer.".into()
        })?;

    let bootstrap_spki = resolve_invite_bootstrap_spki(db, public_spki_hex)?;

    let addrs = if bootstrap_addrs.is_empty() {
        let detected = super::invite_link::detect_bootstrap_addrs(listen_port);
        if detected.is_empty() {
            return Err(
                "No non-loopback addresses detected. Provide --public-addr explicitly.".into(),
            );
        }
        detected
    } else {
        bootstrap_addrs.to_vec()
    };

    let result = create_user_invite(
        db,
        recorded_by,
        &sender_peer_key,
        &sender_peer_eid,
        &admin_event_id,
        &ws_eid,
        &addrs,
        &bootstrap_spki,
    )?;

    Ok(CreateInviteResponse {
        invite_link: result.invite_link,
        invite_event_id: event_id_to_base64(&result.invite_event_id),
    })
}

fn rotate_key_for_recorded_by(
    db: &Connection,
    recorded_by: &str,
) -> Result<RotateKeyResponse, Box<dyn std::error::Error + Send + Sync>> {
    let _ = super::load_local_authoring_context(db, recorded_by)?;
    let result = super::identity_ops::rotate_content_key_for_peer(db, recorded_by)?;
    Ok(RotateKeyResponse {
        key_event_id: event_id_to_base64(&result.key_event_id),
        rotation_event_id: event_id_to_base64(&result.rotation_event_id),
        proactive_share_count: result.proactive_share_count,
    })
}

pub fn create_invite_for_db(
    db_path: &str,
    bootstrap_addrs: &[super::invite_link::BootstrapAddress],
    listen_port: u16,
) -> Result<CreateInviteResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (recorded_by, db) =
        open_db_load(db_path).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("No transport identity: {}", e).into()
        })?;
    create_invite_for_recorded_by(&db, &recorded_by, bootstrap_addrs, listen_port, None)
}

pub fn rotate_key_for_db(
    db_path: &str,
) -> Result<RotateKeyResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (recorded_by, db) =
        open_db_load(db_path).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("No transport identity: {}", e).into()
        })?;
    rotate_key_for_recorded_by(&db, &recorded_by)
}

/// Create invite with an explicit SPKI hex.
pub fn create_invite_with_spki(
    db_path: &str,
    bootstrap_addrs: &[super::invite_link::BootstrapAddress],
    public_spki_hex: &str,
) -> Result<CreateInviteResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (recorded_by, db) =
        open_db_load(db_path).map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("No transport identity: {}", e).into()
        })?;
    create_invite_for_recorded_by(
        &db,
        &recorded_by,
        bootstrap_addrs,
        crate::event_modules::workspace::invite_link::DEFAULT_PORT,
        Some(public_spki_hex),
    )
}

/// Create a user invite for a specific peer (daemon provides the peer_id).
///
/// When `bootstrap_addrs` is empty, auto-detects non-loopback addresses.
pub fn create_invite_for_peer(
    db_path: &str,
    peer_id: &str,
    bootstrap_addrs: &[super::invite_link::BootstrapAddress],
    listen_port: u16,
    public_spki_hex: Option<&str>,
) -> Result<CreateInviteResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (_recorded_by, db) = open_db_for_peer(db_path, peer_id)?;
    create_invite_for_recorded_by(&db, peer_id, bootstrap_addrs, listen_port, public_spki_hex)
}

pub fn rotate_key_for_peer(
    db_path: &str,
    peer_id: &str,
) -> Result<RotateKeyResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (_recorded_by, db) = open_db_for_peer(db_path, peer_id)?;
    rotate_key_for_recorded_by(&db, peer_id)
}

struct PreparedInviteAcceptance {
    db: Connection,
    invite: super::invite_link::ParsedInviteLink,
    invite_key: SigningKey,
    invite_event_id: EventId,
    workspace_id: EventId,
    derived_peer_id: String,
    peer_shared_key: SigningKey,
}

fn prepare_invite_acceptance(
    db_path: &str,
    invite_link_str: &str,
    expected_kind: super::invite_link::InviteLinkKind,
    expected_kind_error: &str,
) -> Result<PreparedInviteAcceptance, Box<dyn std::error::Error + Send + Sync>> {
    use crate::db::{open_connection, schema::create_tables};

    let invite = super::invite_link::parse_invite_link(invite_link_str).map_err(
        |e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("Invalid invite link: {}", e).into()
        },
    )?;
    if invite.kind != expected_kind {
        return Err(expected_kind_error.into());
    }

    let invite_key = invite.invite_signing_key();
    let invite_event_id = invite.invite_event_id;
    let workspace_id = invite.workspace_id;

    // Pre-derive peer_id from PeerShared key so all events are written under
    // the correct recorded_by from the start (no finalize_identity needed).
    let mut rng = rand::thread_rng();
    let peer_shared_key = SigningKey::generate(&mut rng);
    let derived_peer_id = hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
        &peer_shared_key.verifying_key().to_bytes(),
    ));

    // Open DB and ensure schema. Bootstrap transport identity is now installed
    // via invite_accepted projection when local invite_secret material exists.
    let db = {
        let db = open_connection(db_path)?;
        create_tables(&db)?;
        db
    };

    // Record bootstrap context before accept so InviteAccepted projection can
    // materialize trust rows for this tenant. When the invite carries no
    // bootstrap addresses, persist one empty-address marker row so discovery
    // recovery can still use the invite SPKI without generating a bootstrap
    // autodial target.
    let invite_eid_b64 = event_id_to_base64(&invite_event_id);
    let ws_b64 = event_id_to_base64(&workspace_id);
    if invite.bootstrap_addrs.is_empty() {
        crate::db::transport_trust::append_bootstrap_context(
            &db,
            &derived_peer_id,
            &invite_eid_b64,
            &ws_b64,
            "",
            &invite.daemon_spki_fingerprint,
        )?;
    } else {
        for addr in &invite.bootstrap_addrs {
            crate::db::transport_trust::append_bootstrap_context(
                &db,
                &derived_peer_id,
                &invite_eid_b64,
                &ws_b64,
                &addr.to_bootstrap_addr_string(),
                &invite.daemon_spki_fingerprint,
            )?;
        }
    }

    Ok(PreparedInviteAcceptance {
        db,
        invite,
        invite_key,
        invite_event_id,
        workspace_id,
        derived_peer_id,
        peer_shared_key,
    })
}

/// Accept a user invite via projection-first flow.
///
/// NOT async. Parses link, pre-derives PeerShared identity, records bootstrap
/// context, creates identity chain, and persists secrets. No finalize_identity
/// needed — all events are written under the final peer_id from the start.
pub fn accept_invite(
    db_path: &str,
    invite_link_str: &str,
    username: &str,
    devicename: &str,
) -> Result<AcceptInviteResponse, Box<dyn std::error::Error + Send + Sync>> {
    let PreparedInviteAcceptance {
        db,
        invite_key,
        invite_event_id,
        workspace_id,
        derived_peer_id,
        peer_shared_key,
        ..
    } = prepare_invite_acceptance(
        db_path,
        invite_link_str,
        super::invite_link::InviteLinkKind::User,
        "Expected a user invite link (topo://invite/...)",
    )?;

    // Plan.md line 114: at most one workspace instance per daemon endpoint.
    // A user-invite is always a NEW local tenant (fresh PeerShared key), so
    // any existing local-tenant binding for this workspace_id violates the
    // invariant.
    super::uniqueness::assert_endpoint_can_host(&db, &workspace_id)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;

    // Accept the invite: creates identity chain via workspace command API.
    let join = join_workspace_as_new_user(
        &db,
        &derived_peer_id,
        &invite_key,
        &invite_event_id,
        workspace_id,
        username,
        devicename,
        peer_shared_key,
    )?;

    let psf_b64 = event_id_to_base64(&join.peer_shared_event_id);

    // Persist signer secrets.
    persist_join_peer_secret(&db, &derived_peer_id, &join)?;

    Ok(AcceptInviteResponse {
        peer_id: derived_peer_id,
        user_event_id: event_id_to_base64(&join.user_event_id),
        peer_shared_event_id: psf_b64,
    })
}

/// Accept a device link invite via projection-first flow.
///
/// NOT async. Mirrors `accept_invite` but for device-link invites.
/// Pre-derives PeerShared identity so no finalize_identity is needed.
pub fn accept_device_link(
    db_path: &str,
    invite_link_str: &str,
    devicename: &str,
) -> Result<AcceptDeviceLinkResponse, Box<dyn std::error::Error + Send + Sync>> {
    let PreparedInviteAcceptance {
        db,
        invite,
        invite_key,
        invite_event_id,
        workspace_id,
        derived_peer_id,
        peer_shared_key,
    } = prepare_invite_acceptance(
        db_path,
        invite_link_str,
        super::invite_link::InviteLinkKind::DeviceLink,
        "Expected a device link (topo://link/...)",
    )?;

    // Plan.md line 114: at most one workspace instance per daemon endpoint.
    // A device-link accept always creates a new PeerShared (a new local
    // tenant under the post-`recorded_by` model), so the invariant
    // applies even for device-link invites originating from the same
    // user. Device-link is intended to onboard a SECOND machine; running
    // it on a daemon that already hosts the workspace is the violation
    // path that this guard protects against.
    super::uniqueness::assert_endpoint_can_host(&db, &workspace_id)
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.to_string().into() })?;

    let user_event_id = match invite.invite_type {
        super::identity_ops::InviteType::DeviceLink { user_event_id: uid } => uid,
        _ => return Err("Expected DeviceLink invite type".into()),
    };

    // Accept the device link: creates identity chain.
    let link = add_device_to_workspace(
        &db,
        &derived_peer_id,
        &invite_key,
        &invite_event_id,
        workspace_id,
        user_event_id,
        devicename,
        peer_shared_key,
    )?;

    let psf_b64 = event_id_to_base64(&link.peer_shared_event_id);

    // Persist signer secrets.
    persist_link_peer_secret(&db, &derived_peer_id, &link)?;

    Ok(AcceptDeviceLinkResponse {
        peer_id: derived_peer_id,
        peer_shared_event_id: psf_b64,
    })
}

/// Create a device link for a specific peer (daemon provides the peer_id).
///
/// When `bootstrap_addrs` is empty, auto-detects non-loopback addresses.
pub fn create_device_link_for_peer(
    db_path: &str,
    peer_id: &str,
    bootstrap_addrs: &[super::invite_link::BootstrapAddress],
    listen_port: u16,
    public_spki_hex: Option<&str>,
) -> Result<CreateInviteResponse, Box<dyn std::error::Error + Send + Sync>> {
    let (_recorded_by, db) = open_db_for_peer(db_path, peer_id)?;
    let _ = super::load_local_authoring_context(&db, peer_id)?;

    let (sender_peer_eid, sender_peer_key) =
        crate::event_modules::peer_shared::load_local_peer_signer_required(&db, peer_id)?;
    let user_event_id =
        crate::event_modules::peer_shared::resolve_user_event_id(&db, peer_id, &sender_peer_eid)?;

    let workspace_id = super::resolve_workspace_for_peer(&db, peer_id)?;

    let bootstrap_spki = resolve_invite_bootstrap_spki(&db, public_spki_hex)?;

    let addrs = if bootstrap_addrs.is_empty() {
        let detected = super::invite_link::detect_bootstrap_addrs(listen_port);
        if detected.is_empty() {
            return Err(
                "No non-loopback addresses detected. Provide --public-addr explicitly.".into(),
            );
        }
        detected
    } else {
        bootstrap_addrs.to_vec()
    };

    let result = create_device_link_invite(
        &db,
        peer_id,
        &sender_peer_key,
        &sender_peer_eid,
        &user_event_id,
        &workspace_id,
        &addrs,
        &bootstrap_spki,
    )?;

    Ok(CreateInviteResponse {
        invite_link: result.invite_link,
        invite_event_id: event_id_to_base64(&result.invite_event_id),
    })
}

#[cfg(test)]
mod tests {
    use super::resolve_invite_bootstrap_spki;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;
    use crate::runtime::legacy_identity::ensure_daemon_identity;

    #[test]
    fn resolve_invite_bootstrap_spki_uses_daemon_identity_by_default() {
        let db = open_in_memory().expect("open in-memory db");
        create_tables(&db).expect("create tables");
        let (daemon_peer_id, _cert, _key) =
            ensure_daemon_identity(&db).expect("ensure daemon identity");

        let spki = resolve_invite_bootstrap_spki(&db, None).expect("resolve spki");
        let expected: [u8; 32] = hex::decode(daemon_peer_id)
            .unwrap()
            .try_into()
            .expect("daemon peer id bytes");
        assert_eq!(spki, expected);
    }

    #[test]
    fn resolve_invite_bootstrap_spki_accepts_explicit_override() {
        let db = open_in_memory().expect("open in-memory db");
        create_tables(&db).expect("create tables");

        let explicit = hex::encode([0x33; 32]);
        let spki = resolve_invite_bootstrap_spki(&db, Some(&explicit)).expect("resolve spki");
        assert_eq!(spki, [0x33; 32]);
    }
}
