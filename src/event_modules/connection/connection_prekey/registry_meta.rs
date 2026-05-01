//! Registry adapter for `ConnectionPrekeyEvent`.
//!
//! Wires the module into the global `EventRegistry` so the standard event
//! pipeline (parse → project) handles it like any other event. The pure
//! projector verifies the owner endpoint's ed25519 signature directly (the
//! signer is an endpoint identity, not an event-graph signer event), then
//! emits a `Delete` + `InsertOrIgnore` pair to upsert the row keyed by
//! `prekey_id` — matching the original `INSERT OR REPLACE` semantics in
//! `connection/connection_prekey/projector.rs::project`.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use super::event::{ConnectionPrekeyEvent, CONNECTION_PREKEY_TYPE_CODE};
use super::codec::{encode, parse};
use crate::event_modules::registry::{EventTypeMeta, ShareScope};
use crate::event_modules::{EventError, ParsedEvent};
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

fn parse_for_registry(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    parse(blob)
        .map(ParsedEvent::ConnectionPrekey)
        .map_err(|_| EventError::InvalidMetadata("connection_prekey wire decode failed"))
}

fn encode_for_registry(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let ev = match event {
        ParsedEvent::ConnectionPrekey(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    Ok(encode(ev))
}

/// Pure projector adapter: verifies the owner's signature and emits writes
/// for the `connection_prekeys` table. Mirrors `projector::project` but
/// returns `WriteOp`s instead of executing SQL directly.
pub fn project_pure(
    _event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let ev: &ConnectionPrekeyEvent = match parsed {
        ParsedEvent::ConnectionPrekey(v) => v,
        _ => return ProjectorResult::reject("not a connection_prekey event".to_string()),
    };

    // Real ed25519 signature verification — endpoint_id IS the verifying key.
    let vk = match VerifyingKey::from_bytes(&ev.endpoint_id) {
        Ok(vk) => vk,
        Err(_) => {
            return ProjectorResult::reject(
                "connection_prekey endpoint_id is not a valid ed25519 verifying key".to_string(),
            )
        }
    };
    let sig = Signature::from_bytes(&ev.signature);
    if vk.verify(&ev.signing_bytes(), &sig).is_err() {
        return ProjectorResult::reject(
            "connection_prekey signature did not verify".to_string(),
        );
    }

    // Upsert by prekey_id: Delete-then-InsertOrIgnore matches the original
    // INSERT OR REPLACE semantics within the WriteOp contract.
    let ops = vec![
        WriteOp::Delete {
            table: "connection_prekeys",
            where_clause: vec![("prekey_id", SqlVal::Blob(ev.prekey_id.to_vec()))],
        },
        WriteOp::InsertOrIgnore {
            table: "connection_prekeys",
            columns: vec![
                "prekey_id",
                "endpoint_id",
                "private_key",
                "public_key",
                "created_at_ms",
                "ttl_ms",
                "signature",
            ],
            values: vec![
                SqlVal::Blob(ev.prekey_id.to_vec()),
                SqlVal::Blob(ev.endpoint_id.to_vec()),
                SqlVal::Blob(ev.private_key.to_vec()),
                SqlVal::Blob(ev.public_key.to_vec()),
                SqlVal::Int(ev.created_at_ms as i64),
                SqlVal::Int(ev.ttl_ms as i64),
                SqlVal::Blob(ev.signature.to_vec()),
            ],
        },
    ];
    ProjectorResult::valid(ops)
}

pub static CONNECTION_PREKEY_META: EventTypeMeta = EventTypeMeta {
    type_code: CONNECTION_PREKEY_TYPE_CODE,
    type_name: "connection_prekey",
    // TODO(plan.md cutover): connection_prekey is endpoint-local secret state,
    // not a tenant-scoped projection table. `projection_table` is part of the
    // shared EventTypeMeta schema so we point it at the actual table name.
    projection_table: "connection_prekeys",
    // TODO(plan.md cutover): share_scope is a wave-1 concept tied to per-tenant
    // recorded_by routing. Connection events are endpoint-pair scoped; treat
    // them as Local until the recorded_by-removal phase reshapes this enum.
    share_scope: ShareScope::Local,
    dep_fields: &[],
    dep_field_type_codes: &[],
    // Sig verification is done by the projector itself (endpoint identity, not
    // an event-graph signer event), so we mark signer_required: false to skip
    // the pipeline's standard signer-resolution path.
    signer_required: false,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_for_registry,
    encode: encode_for_registry,
    projector: project_pure,
    ensure_schema: Some(super::ensure_schema),
};
