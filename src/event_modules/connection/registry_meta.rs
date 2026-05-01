//! Registry adapter for the top-level `Connection` event (type code 33).
//!
//! Wires the Phase 1 `Connection` struct into the global `EventRegistry`.
//! The pure projector verifies the signer's ed25519 signature directly (the
//! signer is an endpoint identity, not an event-graph signer event), then
//! emits writes for the `connections` table plus one row per shared
//! workspace into `connection_shared_workspaces`.
//!
//! Mirrors `connection_prekey/registry_meta.rs` and
//! `intro/registry_meta.rs`.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use super::event::{Connection, CONNECTION_TYPE_CODE};
use super::codec::{encode_connection, parse_connection};
use crate::event_modules::registry::{EventTypeMeta, ShareScope};
use crate::event_modules::{EventError, ParsedEvent};
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

fn parse_for_registry(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    parse_connection(blob)
        .map(ParsedEvent::Connection)
        .map_err(|_| EventError::InvalidMetadata("connection wire decode failed"))
}

fn encode_for_registry(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let ev = match event {
        ParsedEvent::Connection(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    Ok(encode_connection(ev))
}

/// Pure projector adapter: verifies the signer's signature and emits
/// writes for the `connections` and `connection_shared_workspaces`
/// tables. Mirrors `projector::project` but returns `WriteOp`s instead of
/// executing SQL directly.
pub fn project_pure(
    event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let ev: &Connection = match parsed {
        ParsedEvent::Connection(v) => v,
        _ => return ProjectorResult::reject("not a connection event".to_string()),
    };

    // Real ed25519 signature verification — signer IS the verifying key.
    let vk = match VerifyingKey::from_bytes(&ev.signer) {
        Ok(vk) => vk,
        Err(_) => {
            return ProjectorResult::reject(
                "connection signer is not a valid ed25519 verifying key".to_string(),
            )
        }
    };
    let sig = Signature::from_bytes(&ev.signature);
    if vk.verify(&ev.signing_bytes(), &sig).is_err() {
        return ProjectorResult::reject("connection signature did not verify".to_string());
    }

    // Canonical `connection_id` is the event id the standard parse stage
    // assigns from `hash_event(&blob)` — i.e. Blake2b-256 of the full
    // canonical wire bytes (signature included). The pipeline passes that
    // id in as `event_id_b64`; we decode it here and use it as the row
    // key. If it cannot be decoded (e.g. a unit test passing a placeholder
    // id), we fall back to recomputing it from the canonical bytes so the
    // value is always correct.
    let connection_id = crate::crypto::event_id_from_base64(event_id_b64)
        .unwrap_or_else(|| ev.canonical_event_id());

    let mut ops: Vec<WriteOp> = Vec::new();

    // Upsert by (endpoint_a, endpoint_b, signed_at_ms): Delete-then-
    // InsertOrIgnore matches the original INSERT OR REPLACE semantics
    // within the WriteOp contract (Phase 6a pattern).
    ops.push(WriteOp::Delete {
        table: "connections",
        where_clause: vec![
            ("endpoint_a", SqlVal::Blob(ev.endpoint_a.to_vec())),
            ("endpoint_b", SqlVal::Blob(ev.endpoint_b.to_vec())),
            ("signed_at_ms", SqlVal::Int(ev.signed_at_ms as i64)),
        ],
    });
    ops.push(WriteOp::InsertOrIgnore {
        table: "connections",
        columns: vec![
            "endpoint_a",
            "endpoint_b",
            "signed_at_ms",
            "signer",
            "signature",
            "created_at_ms",
        ],
        values: vec![
            SqlVal::Blob(ev.endpoint_a.to_vec()),
            SqlVal::Blob(ev.endpoint_b.to_vec()),
            SqlVal::Int(ev.signed_at_ms as i64),
            SqlVal::Blob(ev.signer.to_vec()),
            SqlVal::Blob(ev.signature.to_vec()),
            SqlVal::Int(ev.created_at_ms as i64),
        ],
    });

    // Refresh shared-workspaces rows for this connection_id.
    ops.push(WriteOp::Delete {
        table: "connection_shared_workspaces",
        where_clause: vec![("connection_id", SqlVal::Blob(connection_id.to_vec()))],
    });
    for ws in &ev.shared_workspaces {
        ops.push(WriteOp::InsertOrIgnore {
            table: "connection_shared_workspaces",
            columns: vec!["connection_id", "workspace_id"],
            values: vec![
                SqlVal::Blob(connection_id.to_vec()),
                SqlVal::Blob(ws.to_vec()),
            ],
        });
    }

    ProjectorResult::valid(ops)
}

pub static CONNECTION_META: EventTypeMeta = EventTypeMeta {
    type_code: CONNECTION_TYPE_CODE,
    type_name: "connection",
    // TODO(plan.md cutover): see connection_prekey/registry_meta.rs for the
    // share_scope / projection_table caveats. `connection` is endpoint-pair
    // scoped; treat it as Local until the recorded_by-removal phase
    // reshapes the enum.
    projection_table: "connections",
    share_scope: ShareScope::Local,
    dep_fields: &[],
    dep_field_type_codes: &[],
    // Sig verification is done by the projector itself (endpoint identity,
    // not an event-graph signer event), so we mark signer_required: false
    // to skip the pipeline's standard signer-resolution path.
    signer_required: false,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_for_registry,
    encode: encode_for_registry,
    projector: project_pure,
    // The Connection event projector writes `connections` and
    // `connection_shared_workspaces`; the connection family also owns
    // `connection_secrets` (the wrap/unwrap key store). Both are bundled
    // into the umbrella `connection::ensure_schema` so the registry-driven
    // boot pass installs them together.
    ensure_schema: Some(super::ensure_schema),
};
