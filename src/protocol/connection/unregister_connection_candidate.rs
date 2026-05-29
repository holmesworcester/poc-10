//! Connection-maintenance candidate retirement.
//!
//! When a local request is answered — its `connection_response_for_request`
//! context appears — projection emits this replay-allowed intent and the handler
//! removes the request's candidate from the connection-maintenance index through
//! the maintenance-owned helpers. After removal, `maintain_connections` no longer
//! attempts bootstrap sends for that request. Replay reaches the same outcome by
//! reprojecting the request with its response context and dispatching this intent
//! during the replay fixpoint.

use crate::core::effects::PipelineEffects;
use crate::core::intents::{HandlerContext, HandlerResult, Intent, IntentKind, RowMutation, TableDelete};

use crate::protocol::connection::maintenance::index::{candidate_key, CONNECTION_CANDIDATE_ROWS};

/// 32-byte fact id, named locally so this handler file stays off fact-module
/// wire layouts.
pub type FactId = [u8; 32];

pub const UNREGISTER_CONNECTION_CANDIDATE: &str = "unregister_connection_candidate";

pub fn unregister_connection_candidate_intent(request_id: FactId) -> Intent {
    let mut payload = Vec::with_capacity(1 + 32);
    payload.push(1);
    payload.extend_from_slice(&request_id);
    Intent::new(
        IntentKind::new(UNREGISTER_CONNECTION_CANDIDATE)
            .expect("valid unregister connection candidate intent kind"),
        candidate_key(&request_id),
        payload,
    )
}

pub fn decode_unregister_connection_candidate_intent(intent: &Intent) -> Result<FactId, String> {
    if intent.kind.as_str() != UNREGISTER_CONNECTION_CANDIDATE {
        return Err("expected unregister_connection_candidate intent".into());
    }
    if intent.payload.len() != 1 + 32 {
        return Err("unregister_connection_candidate payload has wrong length".into());
    }
    if intent.payload[0] != 1 {
        return Err("unregister_connection_candidate payload version unsupported".into());
    }
    let request_id: FactId = intent.payload[1..33].try_into().unwrap();
    if intent.key != candidate_key(&request_id) {
        return Err("unregister_connection_candidate key does not match payload".into());
    }
    Ok(request_id)
}

#[derive(Debug, Clone, Default)]
pub struct UnregisterConnectionCandidateHandler;

impl UnregisterConnectionCandidateHandler {
    pub fn new() -> Self {
        Self
    }
}

impl crate::core::intents::IntentHandler for UnregisterConnectionCandidateHandler {
    fn handle(&self, intent: &Intent, _context: &HandlerContext) -> HandlerResult {
        let request_id = decode_unregister_connection_candidate_intent(intent)?;
        // Idempotent: deleting an absent candidate is a no-op.
        Ok(PipelineEffects::new().row_mutation(RowMutation::DeleteRow(TableDelete {
            table: CONNECTION_CANDIDATE_ROWS,
            key: candidate_key(&request_id),
        })))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_roundtrips() {
        let intent = unregister_connection_candidate_intent([7; 32]);
        assert_eq!(
            decode_unregister_connection_candidate_intent(&intent).expect("decode"),
            [7; 32]
        );
    }

    #[test]
    fn rejects_tampered_payload() {
        let mut intent = unregister_connection_candidate_intent([7; 32]);
        intent.payload[1] ^= 0xff;
        assert!(decode_unregister_connection_candidate_intent(&intent).is_err());
    }
}
