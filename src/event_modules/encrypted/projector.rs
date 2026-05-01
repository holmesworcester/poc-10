use super::super::ParsedEvent;
use crate::projection::contract::{ContextSnapshot, ProjectorResult};

/// Encrypted events are handled by the pipeline before projector dispatch.
/// If this function is reached, it means the encrypted event was not decrypted.
pub fn project_pure(
    _event_id_b64: &str,
    _parsed: &ParsedEvent,
    _ctx: &ContextSnapshot,
) -> ProjectorResult {
    ProjectorResult::reject("encrypted events should not reach projector dispatch".to_string())
}
