//! Connection maintenance intents.
//!
//! Request projection registers local bootstrap candidates here, but the live
//! retry loop is owned by this module. Replay may rebuild the candidate table
//! from retained request/response facts; live recurring maintenance starts only
//! after replay and turns candidates into local bootstrap send attempts.

use crate::core::effects::PipelineEffects;
use crate::core::{
    facts::FactId,
    intents::{
        HandlerContext, HandlerError, HandlerFactId, HandlerResult, Intent, IntentHandler,
        IntentKind, RowMutation, TableDelete,
    },
    store::Store,
};
use crate::protocol::connection::request::{self, create as request_addr};
use crate::protocol::connection::send_bootstrap_request::{
    send_bootstrap_connection_request_intent, SendBootstrapConnectionRequest,
};
use std::net::SocketAddr;

pub const MAINTAIN_CONNECTIONS: &str = "maintain_connections";
pub const REGISTER_CONNECTION_CANDIDATE: &str = "register_connection_candidate";
pub const UNREGISTER_CONNECTION_CANDIDATE: &str = "unregister_connection_candidate";

const MAINTAIN_PAYLOAD_BYTES: usize = 1 + 8;
const REGISTER_PAYLOAD_BYTES: usize = 1 + 32 + 32 + 32 + 32 + request_addr::ADDR_BLOCK_BYTES;
const UNREGISTER_PAYLOAD_BYTES: usize = 1 + 32;
const VERSION: u8 = 1;
const WORK_LIMIT: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaintainConnections {
    pub now_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegisterConnectionCandidate {
    pub request_id: FactId,
    pub from_endpoint: FactId,
    pub to_endpoint: FactId,
    pub initiator_ephemeral_secret_id: FactId,
    pub addr: SocketAddr,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnregisterConnectionCandidate {
    pub request_id: FactId,
}

pub fn maintain_connections_intent(input: MaintainConnections) -> Intent {
    let mut payload = Vec::with_capacity(MAINTAIN_PAYLOAD_BYTES);
    payload.push(VERSION);
    payload.extend_from_slice(&input.now_ms.to_be_bytes());
    Intent::new(
        IntentKind::new(MAINTAIN_CONNECTIONS).expect("valid maintain connections intent kind"),
        maintain_connections_key(input.now_ms),
        payload,
    )
}

pub fn register_connection_candidate_intent(
    input: RegisterConnectionCandidate,
) -> Result<Intent, String> {
    let mut payload = Vec::with_capacity(REGISTER_PAYLOAD_BYTES);
    payload.push(VERSION);
    payload.extend_from_slice(&input.request_id);
    payload.extend_from_slice(&input.from_endpoint);
    payload.extend_from_slice(&input.to_endpoint);
    payload.extend_from_slice(&input.initiator_ephemeral_secret_id);
    payload.extend_from_slice(&request_addr::encode_optional_addr(Some(input.addr))?);
    Ok(Intent::new(
        IntentKind::new(REGISTER_CONNECTION_CANDIDATE)
            .expect("valid register connection candidate intent kind"),
        connection_candidate_key(&input.request_id),
        payload,
    ))
}

pub fn unregister_connection_candidate_intent(input: UnregisterConnectionCandidate) -> Intent {
    let mut payload = Vec::with_capacity(UNREGISTER_PAYLOAD_BYTES);
    payload.push(VERSION);
    payload.extend_from_slice(&input.request_id);
    Intent::new(
        IntentKind::new(UNREGISTER_CONNECTION_CANDIDATE)
            .expect("valid unregister connection candidate intent kind"),
        connection_candidate_key(&input.request_id),
        payload,
    )
}

pub fn recurring_maintain_connections_intent(
    store: &Store,
    now_ms: u64,
) -> Result<Option<Intent>, String> {
    if request::connection_maintenance_candidate_count(store)? == 0 {
        return Ok(None);
    }
    Ok(Some(maintain_connections_intent(MaintainConnections {
        now_ms,
    })))
}

pub fn decode_maintain_connections(intent: &Intent) -> Result<MaintainConnections, String> {
    if intent.kind.as_str() != MAINTAIN_CONNECTIONS {
        return Err("expected maintain_connections intent".to_string());
    }
    if intent.payload.len() != MAINTAIN_PAYLOAD_BYTES {
        return Err("maintain_connections payload has wrong length".to_string());
    }
    if intent.payload[0] != VERSION {
        return Err("maintain_connections payload version unsupported".to_string());
    }
    let mut now = [0u8; 8];
    now.copy_from_slice(&intent.payload[1..9]);
    let input = MaintainConnections {
        now_ms: u64::from_be_bytes(now),
    };
    if intent.key != maintain_connections_key(input.now_ms) {
        return Err("maintain_connections key does not match payload".to_string());
    }
    Ok(input)
}

pub fn decode_register_connection_candidate(
    intent: &Intent,
) -> Result<RegisterConnectionCandidate, String> {
    if intent.kind.as_str() != REGISTER_CONNECTION_CANDIDATE {
        return Err("expected register_connection_candidate intent".to_string());
    }
    if intent.payload.len() != REGISTER_PAYLOAD_BYTES {
        return Err("register_connection_candidate payload has wrong length".to_string());
    }
    if intent.payload[0] != VERSION {
        return Err("register_connection_candidate payload version unsupported".to_string());
    }
    let request_id = bytes32(&intent.payload[1..33]);
    let from_endpoint = bytes32(&intent.payload[33..65]);
    let to_endpoint = bytes32(&intent.payload[65..97]);
    let initiator_ephemeral_secret_id = bytes32(&intent.payload[97..129]);
    let mut addr_bytes = [0; request_addr::ADDR_BLOCK_BYTES];
    addr_bytes.copy_from_slice(&intent.payload[129..]);
    let addr = request_addr::decode_optional_addr(&addr_bytes)?
        .ok_or_else(|| "register_connection_candidate addr is missing".to_string())?;
    let input = RegisterConnectionCandidate {
        request_id,
        from_endpoint,
        to_endpoint,
        initiator_ephemeral_secret_id,
        addr,
    };
    if intent.key != connection_candidate_key(&input.request_id) {
        return Err("register_connection_candidate key does not match payload".to_string());
    }
    Ok(input)
}

pub fn decode_unregister_connection_candidate(
    intent: &Intent,
) -> Result<UnregisterConnectionCandidate, String> {
    if intent.kind.as_str() != UNREGISTER_CONNECTION_CANDIDATE {
        return Err("expected unregister_connection_candidate intent".to_string());
    }
    if intent.payload.len() != UNREGISTER_PAYLOAD_BYTES {
        return Err("unregister_connection_candidate payload has wrong length".to_string());
    }
    if intent.payload[0] != VERSION {
        return Err("unregister_connection_candidate payload version unsupported".to_string());
    }
    let input = UnregisterConnectionCandidate {
        request_id: bytes32(&intent.payload[1..33]),
    };
    if intent.key != connection_candidate_key(&input.request_id) {
        return Err("unregister_connection_candidate key does not match payload".to_string());
    }
    Ok(input)
}

#[derive(Debug, Clone, Default)]
pub struct RegisterConnectionCandidateHandler;

impl RegisterConnectionCandidateHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for RegisterConnectionCandidateHandler {
    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_register_connection_candidate(intent)?;
        Ok(vec![input.request_id])
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext<'_>) -> HandlerResult {
        let input = decode_register_connection_candidate(intent)?;
        let fact = context.require_fact(&input.request_id)?;
        request::validate_connection_maintenance_candidate(fact, input.into())
            .map_err(HandlerError::fatal)?;
        Ok(PipelineEffects::new().row_mutation(RowMutation::PutRow(
            request::connection_maintenance_candidate_row(input.into())?,
        )))
    }
}

#[derive(Debug, Clone, Default)]
pub struct UnregisterConnectionCandidateHandler;

impl UnregisterConnectionCandidateHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for UnregisterConnectionCandidateHandler {
    fn handle(&self, intent: &Intent, _context: &HandlerContext<'_>) -> HandlerResult {
        let input = decode_unregister_connection_candidate(intent)?;
        Ok(
            PipelineEffects::new().row_mutation(RowMutation::DeleteRow(TableDelete {
                table: request::CONNECTION_MAINTENANCE_CANDIDATE_ROWS,
                key: request::connection_maintenance_candidate_key(&input.request_id),
            })),
        )
    }
}

#[derive(Debug, Clone, Default)]
pub struct MaintainConnectionsHandler;

impl MaintainConnectionsHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for MaintainConnectionsHandler {
    fn handle(&self, intent: &Intent, context: &HandlerContext<'_>) -> HandlerResult {
        decode_maintain_connections(intent)?;
        let candidates = request::connection_maintenance_candidates(context.store()?)?;
        let mut effects = PipelineEffects::new();
        for candidate in candidates.into_iter().take(WORK_LIMIT) {
            effects = effects.local_intent(send_bootstrap_connection_request_intent(
                SendBootstrapConnectionRequest {
                    request_id: candidate.request_id,
                    initiator_ephemeral_secret_id: candidate.initiator_ephemeral_secret_id,
                    addr: candidate.addr,
                },
            )?);
        }
        Ok(effects)
    }
}

fn maintain_connections_key(now_ms: u64) -> Vec<u8> {
    let mut key = b"maintain_connections:".to_vec();
    key.extend_from_slice(&now_ms.to_be_bytes());
    key
}

fn connection_candidate_key(request_id: &FactId) -> Vec<u8> {
    request_id.to_vec()
}

impl From<RegisterConnectionCandidate> for request::ConnectionMaintenanceCandidate {
    fn from(input: RegisterConnectionCandidate) -> Self {
        Self {
            request_id: input.request_id,
            from_endpoint: input.from_endpoint,
            to_endpoint: input.to_endpoint,
            initiator_ephemeral_secret_id: input.initiator_ephemeral_secret_id,
            addr: input.addr,
        }
    }
}

fn bytes32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("slice length checked by caller")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto;
    use crate::core::facts::{Fact, FactScope};
    use crate::core::schema::CORE_SCHEMA_SOURCE;
    use crate::core::store::Store;
    use crate::protocol::connection::request::{
        fact::ConnectionRequestFact, layout as request_layout,
    };
    use crate::protocol::connection::send_bootstrap_request::SEND_BOOTSTRAP_CONNECTION_REQUEST;
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;

    #[test]
    fn intent_roundtrips() {
        let intent = maintain_connections_intent(MaintainConnections { now_ms: 42 });
        let decoded = decode_maintain_connections(&intent).expect("decode");
        assert_eq!(decoded, MaintainConnections { now_ms: 42 });

        let register = RegisterConnectionCandidate {
            request_id: [1; 32],
            from_endpoint: [2; 32],
            to_endpoint: [3; 32],
            initiator_ephemeral_secret_id: [4; 32],
            addr: "127.0.0.1:41001".parse().unwrap(),
        };
        let decoded = decode_register_connection_candidate(
            &register_connection_candidate_intent(register).expect("register intent"),
        )
        .expect("decode register");
        assert_eq!(decoded, register);

        let unregister = UnregisterConnectionCandidate {
            request_id: [1; 32],
        };
        assert_eq!(
            decode_unregister_connection_candidate(&unregister_connection_candidate_intent(
                unregister
            ))
            .expect("decode unregister"),
            unregister
        );
    }

    #[test]
    fn recurring_builder_skips_when_no_candidate_exists() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("open store");
        assert!(recurring_maintain_connections_intent(&store, 1)
            .expect("build recurring")
            .is_none());
    }

    #[test]
    fn recurring_builder_uses_candidate_rows_not_time_wakes() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("open store");
        let candidate = RegisterConnectionCandidate {
            request_id: [1; 32],
            from_endpoint: [2; 32],
            to_endpoint: [3; 32],
            initiator_ephemeral_secret_id: [4; 32],
            addr: "127.0.0.1:41001".parse().unwrap(),
        };
        store
            .insert_table_rows(vec![request::connection_maintenance_candidate_row(
                candidate.into(),
            )
            .expect("candidate row")])
            .expect("insert candidate");

        assert!(recurring_maintain_connections_intent(&store, 123)
            .expect("build recurring")
            .is_some());
    }

    #[test]
    fn register_handler_validates_request_and_writes_candidate_row() {
        let addr = "127.0.0.1:41001".parse().unwrap();
        let request = ConnectionRequestFact {
            from_endpoint: [2; 32],
            to_endpoint: [3; 32],
            nonce: [5; 32],
            invite_fact_id: [6; 32],
            bootstrap_hash: [7; 32],
            invite_signature: [8; crypto::ED25519_SIGNATURE_BYTES],
            invite_secret_fact_id: [9; 32],
            initiator_ephemeral_secret_fact_id: [4; 32],
            initiator_ephemeral_public_key: [10; 32],
            from_listen_addr: None,
            to_listen_addr: Some(addr),
        };
        let fact = Fact::new(
            FactScope::Local,
            1,
            request_layout::encode_fact(&request).expect("request"),
        );
        let input = RegisterConnectionCandidate {
            request_id: fact.id,
            from_endpoint: request.from_endpoint,
            to_endpoint: request.to_endpoint,
            initiator_ephemeral_secret_id: request.initiator_ephemeral_secret_fact_id,
            addr,
        };
        let intent = register_connection_candidate_intent(input).expect("intent");

        let effects = RegisterConnectionCandidateHandler::new()
            .handle(&intent, &HandlerContext::with_facts([fact]))
            .expect("handle register");

        assert_eq!(effects.row_mutations.len(), 1);
        let RowMutation::PutRow(row) = &effects.row_mutations[0] else {
            panic!("expected candidate row");
        };
        let decoded = request::decode_connection_maintenance_candidate_row(&row.key, &row.value)
            .expect("decode candidate");
        assert_eq!(decoded.request_id, input.request_id);
        assert_eq!(decoded.addr, input.addr);
    }

    #[test]
    fn maintain_handler_emits_bootstrap_send_from_candidate_rows() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("open store");
        let candidate = RegisterConnectionCandidate {
            request_id: [1; 32],
            from_endpoint: [2; 32],
            to_endpoint: [3; 32],
            initiator_ephemeral_secret_id: [4; 32],
            addr: "127.0.0.1:41001".parse().unwrap(),
        };
        store
            .insert_table_rows(vec![request::connection_maintenance_candidate_row(
                candidate.into(),
            )
            .expect("candidate row")])
            .expect("insert candidate");
        let intent = maintain_connections_intent(MaintainConnections { now_ms: 123 });

        let effects = MaintainConnectionsHandler::new()
            .handle(&intent, &HandlerContext::new().with_store(&store))
            .expect("maintain connections");

        assert_eq!(effects.local_intents.len(), 1);
        assert_eq!(
            effects.local_intents[0].kind.as_str(),
            SEND_BOOTSTRAP_CONNECTION_REQUEST
        );
    }
}
