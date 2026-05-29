//! Connection-maintenance candidate registration.
//!
//! Connection retry is not owned by historical `connection_request` facts or by
//! a durable wall-clock time wake. Instead, when a local request projects with a
//! reachable bootstrap route and no answer yet, projection emits this
//! replay-allowed intent and the handler records a candidate in the
//! connection-maintenance candidate index. The live `maintain_connections` loop
//! then reads only that index to decide which bootstrap sends to attempt.
//!
//! This file owns the registration intent and handler. The candidate row codec
//! lives in `connection::maintenance::index`; the handler emits the row mutation
//! through that module-owned helper. The candidate row is registration-derived,
//! so replay rebuilds the index deterministically by reprojecting retained
//! request facts. A candidate is removed by `unregister_connection_candidate`
//! once the request is answered.

use std::net::SocketAddr;

use crate::core::effects::PipelineEffects;
use crate::core::intents::{HandlerContext, HandlerResult, Intent, IntentKind, RowMutation};

use crate::protocol::connection::maintenance::index::{candidate_key, candidate_row, CandidateRow};
use crate::protocol::connection::request::create as addr;

/// 32-byte fact id, named locally so this handler file stays off fact-module
/// wire layouts.
pub type FactId = [u8; 32];

pub const REGISTER_CONNECTION_CANDIDATE: &str = "register_connection_candidate";

const VALUE_BYTES: usize = 32 + 32 + addr::ADDR_BLOCK_BYTES;

pub fn register_connection_candidate_intent(candidate: CandidateRow) -> Result<Intent, String> {
    let mut payload = Vec::with_capacity(1 + 32 + VALUE_BYTES);
    payload.push(1);
    payload.extend_from_slice(&candidate.request_id);
    payload.extend_from_slice(&candidate.to_endpoint);
    payload.extend_from_slice(&candidate.initiator_ephemeral_secret_id);
    payload.extend_from_slice(&addr::encode_optional_addr(Some(candidate.addr))?);
    Ok(Intent::new(
        IntentKind::new(REGISTER_CONNECTION_CANDIDATE)
            .expect("valid register connection candidate intent kind"),
        candidate_key(&candidate.request_id),
        payload,
    ))
}

pub fn decode_register_connection_candidate_intent(
    intent: &Intent,
) -> Result<CandidateRow, String> {
    if intent.kind.as_str() != REGISTER_CONNECTION_CANDIDATE {
        return Err("expected register_connection_candidate intent".into());
    }
    if intent.payload.len() != 1 + 32 + VALUE_BYTES {
        return Err("register_connection_candidate payload has wrong length".into());
    }
    if intent.payload[0] != 1 {
        return Err("register_connection_candidate payload version unsupported".into());
    }
    let request_id: FactId = intent.payload[1..33].try_into().unwrap();
    let to_endpoint: FactId = intent.payload[33..65].try_into().unwrap();
    let initiator_ephemeral_secret_id: FactId = intent.payload[65..97].try_into().unwrap();
    let mut addr_bytes = [0u8; addr::ADDR_BLOCK_BYTES];
    addr_bytes.copy_from_slice(&intent.payload[97..]);
    let addr: SocketAddr = addr::decode_optional_addr(&addr_bytes)?
        .ok_or_else(|| "register_connection_candidate addr is missing".to_string())?;
    let candidate = CandidateRow {
        request_id,
        to_endpoint,
        initiator_ephemeral_secret_id,
        addr,
    };
    if intent.key != candidate_key(&candidate.request_id) {
        return Err("register_connection_candidate key does not match payload".into());
    }
    Ok(candidate)
}

#[derive(Debug, Clone, Default)]
pub struct RegisterConnectionCandidateHandler;

impl RegisterConnectionCandidateHandler {
    pub fn new() -> Self {
        Self
    }
}

impl crate::core::intents::IntentHandler for RegisterConnectionCandidateHandler {
    fn handle(&self, intent: &Intent, _context: &HandlerContext) -> HandlerResult {
        let candidate = decode_register_connection_candidate_intent(intent)?;
        // Idempotent: re-registering the same candidate rewrites the same row
        // through the maintenance-owned row helper.
        Ok(PipelineEffects::new().row_mutation(RowMutation::PutRow(candidate_row(&candidate)?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CandidateRow {
        CandidateRow {
            request_id: [1; 32],
            to_endpoint: [2; 32],
            initiator_ephemeral_secret_id: [3; 32],
            addr: "127.0.0.1:41001".parse().unwrap(),
        }
    }

    #[test]
    fn intent_roundtrips() {
        let intent = register_connection_candidate_intent(sample()).expect("intent");
        assert_eq!(
            decode_register_connection_candidate_intent(&intent).expect("decode"),
            sample()
        );
    }

    #[test]
    fn rejects_tampered_key() {
        let mut intent = register_connection_candidate_intent(sample()).expect("intent");
        intent.key[0] ^= 0xff;
        assert!(decode_register_connection_candidate_intent(&intent).is_err());
    }
}
