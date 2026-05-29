//! Connection request family.
//!
//! A request starts a connection handshake from one endpoint to another using
//! invite-backed authorization and initiator ephemeral material. Local commands
//! construct request facts, received network bytes can become durable request
//! facts, and projection validates the branch-specific context before writing a
//! request row or scheduling response work.
//!
//! This family owns request payload bytes, optional listen-address encoding,
//! request row materialization, and request admission policy. Response creation,
//! frame sending, and socket IO belong to the downstream connection modules.

pub mod commands;
pub mod create;
pub mod fact;
pub mod layout;
pub mod project;
pub mod rows;

pub use rows::{
    connection_maintenance_candidate_count, connection_maintenance_candidate_key,
    connection_maintenance_candidate_row, connection_maintenance_candidates,
    decode_connection_maintenance_candidate_row, ConnectionMaintenanceCandidate,
    CONNECTION_MAINTENANCE_CANDIDATE_ROWS,
};

const CONNECTION_RESPONSE_FOR_REQUEST_ROLE: &str = "connection_response_for_request";

pub fn connection_response_for_request_need(
    owner: crate::core::facts::FactId,
    request_id: crate::core::facts::FactId,
) -> crate::core::context::ContextNeed {
    crate::core::context::ContextNeed::range(
        owner,
        crate::core::context::Role::expect(CONNECTION_RESPONSE_FOR_REQUEST_ROLE),
        crate::core::facts::FactScope::Local,
        request_id,
        request_id,
    )
}

pub fn connection_response_for_request_offer(
    owner: crate::core::facts::FactId,
    request_id: crate::core::facts::FactId,
) -> crate::core::context::ContextOffer {
    crate::core::context::ContextOffer::range(
        owner,
        crate::core::context::Role::expect(CONNECTION_RESPONSE_FOR_REQUEST_ROLE),
        crate::core::facts::FactScope::Local,
        request_id,
        request_id,
    )
}

pub fn decode_fact_payload(bytes: &[u8]) -> Result<fact::ConnectionRequestFact, String> {
    layout::decode_fact(bytes)
}

pub fn validate_connection_maintenance_candidate(
    fact: &crate::core::facts::Fact,
    candidate: ConnectionMaintenanceCandidate,
) -> Result<(), String> {
    if fact.scope != crate::core::facts::FactScope::Local {
        return Err("connection candidate request fact must be local".to_string());
    }
    let request = layout::decode_fact(fact.body())?;
    if request.from_endpoint != candidate.from_endpoint {
        return Err("connection candidate from_endpoint does not match request".to_string());
    }
    if request.to_endpoint != candidate.to_endpoint {
        return Err("connection candidate to_endpoint does not match request".to_string());
    }
    if request.initiator_ephemeral_secret_fact_id != candidate.initiator_ephemeral_secret_id {
        return Err("connection candidate ephemeral id does not match request".to_string());
    }
    if request.to_listen_addr != Some(candidate.addr) {
        return Err("connection candidate addr does not match request".to_string());
    }
    Ok(())
}

pub(crate) struct Codec;

impl crate::core::projectors::FactCodec for Codec {
    type Payload = fact::ConnectionRequestFact;

    fn decode_fact(fact: &crate::core::facts::Fact) -> Result<Self::Payload, String> {
        decode_fact_payload(fact.body())
    }
}
