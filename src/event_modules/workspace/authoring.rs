use ed25519_dalek::SigningKey;
use rusqlite::Connection;

use crate::crypto::{event_id_to_base64, EventId};
use crate::event_modules::peer_shared;

use super::queries::resolve_workspace_for_peer;

pub struct LocalAuthoringContext {
    pub signer_event_id: EventId,
    pub signing_key: SigningKey,
    pub workspace_id: [u8; 32],
    pub author_id: [u8; 32],
}

pub fn load_local_authoring_context(
    db: &Connection,
    recorded_by: &str,
) -> Result<LocalAuthoringContext, Box<dyn std::error::Error + Send + Sync>> {
    let (signer_event_id, signing_key) =
        peer_shared::load_local_peer_signer_required(db, recorded_by)?;
    let workspace_id = resolve_workspace_for_peer(db, recorded_by)?;
    let author_id = peer_shared::resolve_user_event_id(db, recorded_by, &signer_event_id)?;
    let workspace_id_b64 = event_id_to_base64(&workspace_id);
    let author_id_b64 = event_id_to_base64(&author_id);

    // Plan.md Stage 2: `workspaces` PK migrated from
    // `(recorded_by, event_id)` to `(workspace_id, event_id)` — there is
    // now at most one row per workspace_id, regardless of which tenant
    // last projected it. Per-tenant readiness is satisfied by the
    // `invites_accepted` check (still keyed by recorded_by in Stage 2)
    // PLUS a global existence check on `workspaces`. A row in
    // `invites_accepted` for this tenant proves the tenant joined the
    // workspace; the `workspaces` row proves the root event has
    // projected somewhere.
    let workspace_projected: bool = db.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM workspaces
             WHERE workspace_id = ?1
         )",
        rusqlite::params![workspace_id_b64],
        |row| row.get(0),
    )?;
    // Plan.md Stage 2: `users` PK migrated to `(workspace_id, event_id)`.
    // The same user event projects under a single global row, so check by
    // event_id alone.
    let _ = recorded_by;
    let author_projected: bool = db.query_row(
        "SELECT EXISTS(
             SELECT 1
             FROM users
             WHERE event_id = ?1
         )",
        rusqlite::params![author_id_b64],
        |row| row.get(0),
    )?;
    if !workspace_projected || !author_projected {
        return Err(
            "workspace has not completed initial sync yet — local authoring deps are still syncing"
                .into(),
        );
    }

    Ok(LocalAuthoringContext {
        signer_event_id,
        signing_key,
        workspace_id,
        author_id,
    })
}
