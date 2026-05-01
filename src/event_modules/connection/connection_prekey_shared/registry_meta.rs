//! Registry adapter for `ConnectionPrekeySharedEvent`.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use super::event::{ConnectionPrekeySharedEvent, CONNECTION_PREKEY_SHARED_TYPE_CODE};
use super::codec::{encode, parse};
use crate::event_modules::registry::{EventTypeMeta, ShareScope};
use crate::event_modules::{EventError, ParsedEvent};
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

fn parse_for_registry(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    parse(blob)
        .map(ParsedEvent::ConnectionPrekeyShared)
        .map_err(|_| EventError::InvalidMetadata("connection_prekey_shared wire decode failed"))
}

fn encode_for_registry(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let ev = match event {
        ParsedEvent::ConnectionPrekeyShared(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    Ok(encode(ev))
}

pub fn project_pure(
    _event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let ev: &ConnectionPrekeySharedEvent = match parsed {
        ParsedEvent::ConnectionPrekeyShared(v) => v,
        _ => return ProjectorResult::reject("not a connection_prekey_shared event".to_string()),
    };

    let vk = match VerifyingKey::from_bytes(&ev.endpoint_id) {
        Ok(vk) => vk,
        Err(_) => {
            return ProjectorResult::reject(
                "connection_prekey_shared endpoint_id is not a valid ed25519 verifying key"
                    .to_string(),
            )
        }
    };
    let sig = Signature::from_bytes(&ev.signature);
    if vk.verify(&ev.signing_bytes(), &sig).is_err() {
        return ProjectorResult::reject(
            "connection_prekey_shared signature did not verify".to_string(),
        );
    }

    // Original projector uses INSERT OR IGNORE — first writer wins per
    // (prekey_id) primary key. No delete needed.
    let ops = vec![WriteOp::InsertOrIgnore {
        table: "connection_prekeys_shared",
        columns: vec![
            "prekey_id",
            "endpoint_id",
            "public_key",
            "created_at_ms",
            "ttl_ms",
            "signature",
        ],
        values: vec![
            SqlVal::Blob(ev.prekey_id.to_vec()),
            SqlVal::Blob(ev.endpoint_id.to_vec()),
            SqlVal::Blob(ev.public_key.to_vec()),
            SqlVal::Int(ev.created_at_ms as i64),
            SqlVal::Int(ev.ttl_ms as i64),
            SqlVal::Blob(ev.signature.to_vec()),
        ],
    }];
    ProjectorResult::valid(ops)
}

pub static CONNECTION_PREKEY_SHARED_META: EventTypeMeta = EventTypeMeta {
    type_code: CONNECTION_PREKEY_SHARED_TYPE_CODE,
    type_name: "connection_prekey_shared",
    // TODO(plan.md cutover): see connection_prekey/registry_meta.rs.
    projection_table: "connection_prekeys_shared",
    share_scope: ShareScope::Shared,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 64,
    encryptable: false,
    parse: parse_for_registry,
    encode: encode_for_registry,
    projector: project_pure,
    ensure_schema: Some(super::ensure_schema),
};
