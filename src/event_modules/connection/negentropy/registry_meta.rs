//! Registry adapter for `NegentropyEvent`.
//!
//! Wire-only: no signature, no durable write. The pure projector returns
//! Valid with no `WriteOp`s — the control_loop picks the parsed event up
//! from the work queue and acts on it. Registering the event in the registry
//! keeps parse + dedupe-by-id consistent with every other event type.

use super::event::NEGENTROPY_TYPE_CODE;
use super::codec::{encode, parse};
use crate::event_modules::registry::{EventTypeMeta, ShareScope};
use crate::event_modules::{EventError, ParsedEvent};
use crate::projection::contract::{ContextSnapshot, ProjectorResult};

fn parse_for_registry(blob: &[u8]) -> Result<ParsedEvent, EventError> {
    parse(blob)
        .map(ParsedEvent::Negentropy)
        .map_err(|_| EventError::InvalidMetadata("negentropy wire decode failed"))
}

fn encode_for_registry(event: &ParsedEvent) -> Result<Vec<u8>, EventError> {
    let ev = match event {
        ParsedEvent::Negentropy(v) => v,
        _ => return Err(EventError::WrongVariant),
    };
    Ok(encode(ev))
}

pub fn project_pure(
    _event_id_b64: &str,
    parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    if !matches!(parsed, ParsedEvent::Negentropy(_)) {
        return ProjectorResult::reject("not a negentropy event".to_string());
    }
    // Wire-only: nothing to write. Control_loop picks up the parsed event
    // from the work queue and emits subsequent intents.
    ProjectorResult::valid(Vec::new())
}

pub static NEGENTROPY_META: EventTypeMeta = EventTypeMeta {
    type_code: NEGENTROPY_TYPE_CODE,
    type_name: "negentropy",
    // TODO(plan.md cutover): no durable table — name retained for diagnostics.
    projection_table: "(none)",
    share_scope: ShareScope::Local,
    dep_fields: &[],
    dep_field_type_codes: &[],
    signer_required: false,
    signature_byte_len: 0,
    encryptable: false,
    parse: parse_for_registry,
    encode: encode_for_registry,
    projector: project_pure,
    ensure_schema: None,
};
