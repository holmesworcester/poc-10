use super::super::ParsedEvent;
use crate::contracts::transport_identity_contract::TransportIdentitySpec;
use crate::crypto::event_id_to_base64;
use crate::projection::contract::{ContextSnapshot, EmitCommand, ProjectorResult, SqlVal, WriteOp};
use rusqlite::Connection;

/// `peer_secrets` projection table.
///
/// Plan.md round-9 step 4 — primary key migration:
/// `(recorded_by, event_id)` → `(workspace_id, peer_id)`. The new key
/// reflects the post-`recorded_by` model: a peer secret is the local
/// peer's private key material for one workspace, uniquely identified by
/// the workspace it scopes to and the peer_id it materialises into.
///
/// `secret_event_id` (the event-id of the peer_secret event itself) is
/// retained as a UNIQUE column so the chain still has an idempotency
/// key for replay. `signer_event_id` is preserved for transport
/// identity adapter lookups.
///
/// For poc-8 dev we DROP+CREATE on schema-init when the existing PK
/// shape doesn't match the new key.
pub fn ensure_schema(conn: &Connection) -> rusqlite::Result<()> {
    let needs_recreate = match pk_columns(conn, "peer_secrets")? {
        Some(cols) => cols != vec!["workspace_id".to_string(), "peer_id".to_string()],
        None => false, // table doesn't exist yet — create fresh below
    };
    if needs_recreate {
        conn.execute_batch("DROP TABLE IF EXISTS peer_secrets")?;
    }
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS peer_secrets (
            workspace_id TEXT NOT NULL,
            peer_id TEXT NOT NULL,
            secret_event_id TEXT NOT NULL UNIQUE,
            signer_event_id TEXT NOT NULL,
            private_key BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (workspace_id, peer_id)
        );
        CREATE INDEX IF NOT EXISTS idx_peer_secrets_signer
            ON peer_secrets(signer_event_id, created_at DESC, secret_event_id DESC);
        CREATE INDEX IF NOT EXISTS idx_peer_secrets_peer
            ON peer_secrets(peer_id, created_at DESC, secret_event_id DESC);
        ",
    )?;
    Ok(())
}

/// Read the PRIMARY KEY column names for `table`, in PK ordinal order.
/// Returns `None` if the table does not exist.
fn pk_columns(conn: &Connection, table: &str) -> rusqlite::Result<Option<Vec<String>>> {
    let pragma = format!("PRAGMA table_info({})", table);
    let mut stmt = conn.prepare(&pragma)?;
    let mut rows = stmt.query([])?;
    let mut found_any = false;
    let mut pks: Vec<(i64, String)> = Vec::new();
    while let Some(row) = rows.next()? {
        found_any = true;
        let name: String = row.get(1)?;
        let pk: i64 = row.get(5)?;
        if pk > 0 {
            pks.push((pk, name));
        }
    }
    if !found_any {
        return Ok(None);
    }
    pks.sort_by_key(|p| p.0);
    Ok(Some(pks.into_iter().map(|p| p.1).collect()))
}

/// Pure projector: PeerSecret -> peer_secrets table (one row per peer/workspace).
/// Always emits MaterializeTransportIdentity(InstallPeerSharedIdentityFromSigner).
pub fn project_pure(
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let e = match parsed {
        ParsedEvent::PeerSecret(v) => v,
        _ => return ProjectorResult::reject("not a peer_secret event".to_string()),
    };

    let signer_eid_b64 = event_id_to_base64(&e.signer_event_id);
    let workspace_id_b64 = event_id_to_base64(&e.workspace_id);

    // Derive the peer_id from the private key material in the event.
    // This is the same hex SPKI fingerprint used by `local_transport_creds`
    // and downstream transport identity install.
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&e.private_key_bytes);
    let public_key = signing_key.verifying_key().to_bytes();
    let peer_id = hex::encode(crate::crypto::spki_fingerprint_from_ed25519_pubkey(
        &public_key,
    ));

    // Stage 3.5 hold-over: the transport identity adapter still takes a
    // `recorded_by` field today; keep the legacy bridge value in the
    // emit command until the adapter signature is migrated. Chain-only
    // callers fall back to a sentinel.
    let recorded_by_sentinel = crate::projection::apply::dispatch::current_recorded_by()
        .unwrap_or_else(|| "__chain__".to_string());

    ProjectorResult::valid_with_commands(
        vec![WriteOp::InsertOrIgnore {
            table: "peer_secrets",
            columns: vec![
                "workspace_id",
                "peer_id",
                "secret_event_id",
                "signer_event_id",
                "private_key",
                "created_at",
            ],
            values: vec![
                SqlVal::Text(workspace_id_b64),
                SqlVal::Text(peer_id),
                SqlVal::Text(event_id_b64.to_string()),
                SqlVal::Text(signer_eid_b64),
                SqlVal::Blob(e.private_key_bytes.to_vec()),
                SqlVal::Int(e.created_at_ms as i64),
            ],
        }],
        vec![EmitCommand::MaterializeTransportIdentity {
            spec: TransportIdentitySpec::InstallPeerSharedIdentityFromSigner {
                recorded_by: recorded_by_sentinel,
                signer_event_id: e.signer_event_id,
            },
        }],
    )
}
