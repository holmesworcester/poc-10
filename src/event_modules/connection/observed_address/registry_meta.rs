//! Registry adapter for `ObservedAddressEvent`.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use super::event::{ObservedAddressEvent, OBSERVED_ADDRESS_TYPE_CODE};
use super::codec::{encode, parse};
use crate::event_modules::registry::{EventTypeMeta, ShareScope};
use crate::event_modules::{EventError, ParsedEvent};
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

fn parse_for_registry(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    parse(blob)
        .map(ParsedEvent::ObservedAddress)
        .map_err(|_| EventError::InvalidMetadata("observed_address wire decode failed"))
}

fn encode_for_registry(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let ev = match event {
        ParsedEvent::ObservedAddress(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    Ok(encode(ev))
}

pub fn project_pure(
    _event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let ev: &ObservedAddressEvent = match parsed {
        ParsedEvent::ObservedAddress(v) => v,
        _ => return ProjectorResult::reject("not an observed_address event".to_string()),
    };

    let vk = match VerifyingKey::from_bytes(&ev.signed_by) {
        Ok(vk) => vk,
        Err(_) => {
            return ProjectorResult::reject(
                "observed_address signed_by is not a valid ed25519 verifying key".to_string(),
            )
        }
    };
    let sig = Signature::from_bytes(&ev.signature);
    if vk.verify(&ev.signing_bytes(), &sig).is_err() {
        return ProjectorResult::reject(
            "observed_address signature did not verify".to_string(),
        );
    }

    // Original projector uses INSERT OR REPLACE keyed by
    // (observer, subject, ip, port). Reproduce as Delete-then-Insert.
    let pk_where = vec![
        ("observer_endpoint_id", SqlVal::Blob(ev.observer_endpoint_id.to_vec())),
        ("subject_endpoint_id", SqlVal::Blob(ev.subject_endpoint_id.to_vec())),
        ("ip", SqlVal::Blob(ev.ip.to_vec())),
        ("port", SqlVal::Int(ev.port as i64)),
    ];
    let ops = vec![
        WriteOp::Delete {
            table: "observed_addresses",
            where_clause: pk_where,
        },
        WriteOp::InsertOrIgnore {
            table: "observed_addresses",
            columns: vec![
                "observer_endpoint_id",
                "subject_endpoint_id",
                "ip",
                "port",
                "observed_at_ms",
                "ttl_ms",
                "signed_by",
                "signature",
            ],
            values: vec![
                SqlVal::Blob(ev.observer_endpoint_id.to_vec()),
                SqlVal::Blob(ev.subject_endpoint_id.to_vec()),
                SqlVal::Blob(ev.ip.to_vec()),
                SqlVal::Int(ev.port as i64),
                SqlVal::Int(ev.observed_at_ms as i64),
                SqlVal::Int(ev.ttl_ms as i64),
                SqlVal::Blob(ev.signed_by.to_vec()),
                SqlVal::Blob(ev.signature.to_vec()),
            ],
        },
    ];
    ProjectorResult::valid(ops)
}

pub static OBSERVED_ADDRESS_META: EventTypeMeta = EventTypeMeta {
    type_code: OBSERVED_ADDRESS_TYPE_CODE,
    type_name: "observed_address",
    // TODO(plan.md cutover): see connection_prekey/registry_meta.rs.
    projection_table: "observed_addresses",
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
