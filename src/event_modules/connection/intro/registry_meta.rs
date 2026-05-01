//! Registry adapter for `IntroEvent`.
//!
//! Like the original `projector::project`, this adapter writes one row per
//! (intro_id, subject_endpoint_id, ip, port) tuple — including a sentinel
//! row per subject when no addresses were carried.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use super::event::{IntroEvent, INTRO_TYPE_CODE};
use super::codec::{encode, parse};
use crate::event_modules::registry::{EventTypeMeta, ShareScope};
use crate::event_modules::{EventError, ParsedEvent};
use crate::projection::contract::{ContextSnapshot, ProjectorResult, SqlVal, WriteOp};

fn parse_for_registry(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    parse(blob)
        .map(ParsedEvent::Intro)
        .map_err(|_| EventError::InvalidMetadata("intro wire decode failed"))
}

fn encode_for_registry(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let ev = match event {
        ParsedEvent::Intro(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    Ok(encode(ev))
}

/// Compute a deterministic intro_id from the event content. Mirrors
/// `projector::intro_id` (private). Kept here so the pure projector can
/// build write ops without invoking the original `project` impl.
fn intro_id(ev: &IntroEvent) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"poc8-intro-id-v1");
    h.update(&ev.signing_bytes());
    h.update(&ev.signature);
    let out = h.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(out.as_bytes());
    id
}

pub fn project_pure(
    _event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    let ev: &IntroEvent = match parsed {
        ParsedEvent::Intro(v) => v,
        _ => return ProjectorResult::reject("not an intro event".to_string()),
    };

    let vk = match VerifyingKey::from_bytes(&ev.signed_by) {
        Ok(vk) => vk,
        Err(_) => {
            return ProjectorResult::reject(
                "intro signed_by is not a valid ed25519 verifying key".to_string(),
            )
        }
    };
    let sig = Signature::from_bytes(&ev.signature);
    if vk.verify(&ev.signing_bytes(), &sig).is_err() {
        return ProjectorResult::reject("intro signature did not verify".to_string());
    }

    let id = intro_id(ev);
    let mut ops: Vec<WriteOp> = Vec::new();

    let push_row = |ops: &mut Vec<WriteOp>,
                    subject: &[u8; 32],
                    other: &[u8; 32],
                    ip: Vec<u8>,
                    port: i64| {
        ops.push(WriteOp::InsertOrIgnore {
            table: "intros",
            columns: vec![
                "intro_id",
                "introducer_endpoint",
                "subject_endpoint_id",
                "other_subject_id",
                "ip",
                "port",
                "created_at_ms",
            ],
            values: vec![
                SqlVal::Blob(id.to_vec()),
                SqlVal::Blob(ev.signed_by.to_vec()),
                SqlVal::Blob(subject.to_vec()),
                SqlVal::Blob(other.to_vec()),
                SqlVal::Blob(ip),
                SqlVal::Int(port),
                SqlVal::Int(ev.created_at_ms as i64),
            ],
        });
    };

    for a in &ev.addresses_a {
        push_row(
            &mut ops,
            &ev.subject_a_endpoint_id,
            &ev.subject_b_endpoint_id,
            a.ip.to_vec(),
            a.port as i64,
        );
    }
    for a in &ev.addresses_b {
        push_row(
            &mut ops,
            &ev.subject_b_endpoint_id,
            &ev.subject_a_endpoint_id,
            a.ip.to_vec(),
            a.port as i64,
        );
    }
    if ev.addresses_a.is_empty() {
        push_row(
            &mut ops,
            &ev.subject_a_endpoint_id,
            &ev.subject_b_endpoint_id,
            vec![0u8; 16],
            0,
        );
    }
    if ev.addresses_b.is_empty() {
        push_row(
            &mut ops,
            &ev.subject_b_endpoint_id,
            &ev.subject_a_endpoint_id,
            vec![0u8; 16],
            0,
        );
    }

    ProjectorResult::valid(ops)
}

pub static INTRO_META: EventTypeMeta = EventTypeMeta {
    type_code: INTRO_TYPE_CODE,
    type_name: "intro",
    // TODO(plan.md cutover): see connection_prekey/registry_meta.rs.
    projection_table: "intros",
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
