//! Registry adapter for `SelfAddressEvent`.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use super::event::{SelfAddressEvent, SELF_ADDRESS_TYPE_CODE};
use super::codec::{encode, parse};
use crate::event_modules::registry::{EventTypeMeta, ShareScope};
use crate::event_modules::{EventError, ParsedEvent};
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

fn parse_for_registry(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    parse(blob)
        .map(ParsedEvent::SelfAddress)
        .map_err(|_| EventError::InvalidMetadata("self_address wire decode failed"))
}

fn encode_for_registry(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let ev = match event {
        ParsedEvent::SelfAddress(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    Ok(encode(ev))
}

pub fn project_pure(
    _event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let ev: &SelfAddressEvent = match parsed {
        ParsedEvent::SelfAddress(v) => v,
        _ => return ProjectorResult::reject("not a self_address event".to_string()),
    };

    if ev.signed_by != ev.endpoint_id {
        return ProjectorResult::reject(
            "self_address signed_by must equal endpoint_id".to_string(),
        );
    }
    let vk = match VerifyingKey::from_bytes(&ev.endpoint_id) {
        Ok(vk) => vk,
        Err(_) => {
            return ProjectorResult::reject(
                "self_address endpoint_id is not a valid ed25519 verifying key".to_string(),
            )
        }
    };
    let sig = Signature::from_bytes(&ev.signature);
    if vk.verify(&ev.signing_bytes(), &sig).is_err() {
        return ProjectorResult::reject("self_address signature did not verify".to_string());
    }

    // Original uses INSERT OR REPLACE keyed by (endpoint_id, ip, port).
    let pk_where = vec![
        ("endpoint_id", SqlVal::Blob(ev.endpoint_id.to_vec())),
        ("ip", SqlVal::Blob(ev.ip.to_vec())),
        ("port", SqlVal::Int(ev.port as i64)),
    ];
    let ops = vec![
        WriteOp::Delete {
            table: "self_addresses",
            where_clause: pk_where,
        },
        WriteOp::InsertOrIgnore {
            table: "self_addresses",
            columns: vec![
                "endpoint_id",
                "ip",
                "port",
                "created_at_ms",
                "ttl_ms",
                "signed_by",
                "signature",
            ],
            values: vec![
                SqlVal::Blob(ev.endpoint_id.to_vec()),
                SqlVal::Blob(ev.ip.to_vec()),
                SqlVal::Int(ev.port as i64),
                SqlVal::Int(ev.created_at_ms as i64),
                SqlVal::Int(ev.ttl_ms as i64),
                SqlVal::Blob(ev.signed_by.to_vec()),
                SqlVal::Blob(ev.signature.to_vec()),
            ],
        },
    ];
    ProjectorResult::valid(ops)
}

pub static SELF_ADDRESS_META: EventTypeMeta = EventTypeMeta {
    type_code: SELF_ADDRESS_TYPE_CODE,
    type_name: "self_address",
    // TODO(plan.md cutover): see connection_prekey/registry_meta.rs.
    projection_table: "self_addresses",
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
