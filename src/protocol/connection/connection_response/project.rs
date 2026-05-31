//! Membership connection-response projector.
//!
//! Response projection turns a validated membership handshake answer into local
//! connection state. Both branches prove exact membership-request context and
//! recompute the Diffie-Hellman handshake. Received responses additionally prove
//! a fact receipt and the initiator ephemeral secret; local responses prove the
//! responder ephemeral secret and emit the network send (flat-intent rule:
//! `create_connection_response` only creates facts; this projector sends).
//!
//! The materialized row is written into the shared connection table keyed by
//! connection id, identical to bootstrap connections, so established frames and
//! sync are agnostic to how the connection was authorized.
//!
//! POLICY. A connection_response is admitted iff:
//!   1. STRUCTURAL. The fact is local-only, response fields are non-empty, and
//!      the response references a different request fact.
//!   2. CONTEXT. Projection validates exact membership-request context and the
//!      Diffie-Hellman handshake. Received responses additionally require a fact
//!      receipt plus the local initiator secret; local responses require the
//!      responder secret. Close context removes the row and purges the fact.
//!   3. MATERIALIZE. Valid responses write the shared connection row and publish
//!      local connection context. Received responses seed the initial sync;
//!      local responses emit the network send.
//!
//! Change this projector for membership response admission and sync seeding.
//! Byte layout lives in `layout.rs`; key-schedule construction in `create.rs`.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::{RowMutation, TableDelete};
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use crate::protocol::connection::bootstrap_response::rows::{
    bootstrap_response_key, connection_row, ConnectionRowFields, BOOTSTRAP_RESPONSE_ROWS,
};
use crate::protocol::connection::connection_request as request_family;
use crate::protocol::connection::fact_receipt::{self, fact::RECEIVE_PATH_CONNECTION_RESPONSE};
use crate::protocol::connection::send_connection_response::{
    send_connection_response_intent, SendConnectionResponse,
};
use crate::protocol::connection::{close, ephemeral_secret};
use crate::protocol::sync::seed_connection::{seed_connection_sync_intent, SeedConnectionSync};

use super::create;
use super::fact::ConnectionResponseFact;

#[derive(Debug, Clone, Default)]
pub struct ConnectionResponseProjector;

impl ConnectionResponseProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionResponseProjector {
    fn project(
        &self,
        fact: &Fact,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, projection_context)
    }
}

impl TypedProjector<super::Codec> for ConnectionResponseProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        response: ConnectionResponseFact,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Local {
            return Err("membership connection response fact must have local scope".to_string());
        }
        validate_response_fields(&response)?;
        if response.from_endpoint == response.to_endpoint {
            return Err("membership connection response endpoints must differ".to_string());
        }
        if response.request_id == fact.id {
            return Err("membership connection response cannot answer itself".to_string());
        }

        // 2. Close gate.
        let close_need = close::connection_closed_need(fact.id, fact.id);
        if let Some(close_fact) = projection_context.payload_for(&close_need) {
            if close_fact.scope != FactScope::Local {
                return Err("membership connection response close context must be local".to_string());
            }
            let close = close::decode_fact_payload(close_fact.body()).map_err(|_| {
                "membership connection response close context is not a connection close".to_string()
            })?;
            if close.connection_id != fact.id {
                return Err(
                    "membership connection response close context targets another connection".into(),
                );
            }
            return closed_output(fact.id);
        }

        // 2. Request context (membership request only).
        let request_need = request_family::connection_request_need(fact.id, response.request_id);
        let Some(request_context) = projection_context.payload_for(&request_need) else {
            return Ok(waiting_output([request_need]));
        };
        let request = request_family::decode_fact_payload(request_context.body())
            .map_err(|_| "membership connection response context is not a request fact".to_string())?;
        if request_context.id != response.request_id {
            return Err(
                "membership connection response request context id does not match response"
                    .to_string(),
            );
        }
        if !matches!(request_context.scope, FactScope::Local | FactScope::Global) {
            return Err(
                "membership connection response request context has unsupported scope".to_string(),
            );
        }
        validate_request_response(&response, &request)?;
        if response.handshake_hash
            != create::public_handshake_hash(
                response.request_id,
                &request,
                &response.responder_ephemeral_public_key,
            )
        {
            return Err(
                "membership connection response handshake hash does not match transcript"
                    .to_string(),
            );
        }

        let responder_ephemeral_need = ephemeral_need(fact.id, response.responder_ephemeral_secret_fact_id);
        let receive_need = crate::core::context::ContextNeed::range(
            fact.id,
            "connection_fact_receipt",
            FactScope::Local,
            fact.id,
            fact.id,
        );

        if let Some(receive) = projection_context
            .matched_payloads_for(&receive_need)
            .map(|(_, fact)| fact)
            .min_by_key(|fact| fact.id)
        {
            // 2a. Received response path.
            if receive.scope != FactScope::Local {
                return Err(
                    "membership connection response receive context must be local".to_string(),
                );
            }
            let received = fact_receipt::decode_fact_payload(receive.body()).map_err(|_| {
                "membership connection response receive context is not connection fact receipt"
                    .to_string()
            })?;
            validate_fact_receipt(fact.id, &response, &received)?;
            let initiator_ephemeral_need =
                ephemeral_need(fact.id, response.initiator_ephemeral_secret_fact_id);
            let Some(initiator_ephemeral) =
                projection_context.payload_for(&initiator_ephemeral_need)
            else {
                return Ok(waiting_output([
                    request_need,
                    initiator_ephemeral_need,
                    receive_need,
                ]));
            };
            let initiator_secret =
                ephemeral_secret::decode_fact_payload(initiator_ephemeral.body()).map_err(|_| {
                    "membership connection response initiator dependency is not an ephemeral secret"
                        .to_string()
                })?;
            if initiator_ephemeral.id != response.initiator_ephemeral_secret_fact_id {
                return Err(
                    "membership connection response initiator ephemeral context id does not match"
                        .to_string(),
                );
            }
            if initiator_ephemeral.scope != FactScope::Local {
                return Err(
                    "membership connection response initiator ephemeral context must be local"
                        .to_string(),
                );
            }
            let material = create::initiator_material(
                response.request_id,
                &request,
                &initiator_secret,
                &response.responder_ephemeral_public_key,
            )?;
            if response.connection_secret != material.connection_secret {
                return Err(
                    "membership connection response secret does not match handshake".to_string(),
                );
            }
            return materialized_output(fact, &response, SeedSync::Immediate);
        }

        // 2b. Local response path.
        let Some(responder_ephemeral) = projection_context.payload_for(&responder_ephemeral_need)
        else {
            return Ok(waiting_output([
                request_need,
                responder_ephemeral_need,
                receive_need,
            ]));
        };
        let responder_secret = ephemeral_secret::decode_fact_payload(responder_ephemeral.body())
            .map_err(|_| {
                "membership connection response responder dependency is not an ephemeral secret"
                    .to_string()
            })?;
        if responder_ephemeral.id != response.responder_ephemeral_secret_fact_id {
            return Err(
                "membership connection response responder ephemeral context id does not match"
                    .to_string(),
            );
        }
        if responder_ephemeral.scope != FactScope::Local {
            return Err(
                "membership connection response responder ephemeral context must be local"
                    .to_string(),
            );
        }
        if responder_secret.owner_endpoint != response.from_endpoint {
            return Err(
                "membership connection response responder ephemeral owner does not match sender"
                    .to_string(),
            );
        }
        if responder_secret.ephemeral_public_key != response.responder_ephemeral_public_key {
            return Err(
                "membership connection response responder ephemeral public key does not match dependency"
                    .to_string(),
            );
        }
        // 3. Materialize the local response and queue its send. Flat-intent
        // rule: create_connection_response only creates the responder ephemeral
        // and response facts; this projector emits the send once the local
        // response fact is admitted.
        let mut output = materialized_output(fact, &response, SeedSync::None)?;
        if let Some(addr) = request.from_listen_addr {
            output = output.intent(send_connection_response_intent(SendConnectionResponse {
                response_id: fact.id,
                responder_ephemeral_secret_id: response.responder_ephemeral_secret_fact_id,
                addr,
            })?);
        }
        Ok(output)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeedSync {
    None,
    Immediate,
}

fn ephemeral_need(owner: [u8; 32], secret_id: [u8; 32]) -> crate::core::context::ContextNeed {
    crate::core::context::ContextNeed::range(
        owner,
        "connection_ephemeral_secret",
        FactScope::Local,
        secret_id,
        secret_id,
    )
}

fn validate_response_fields(response: &ConnectionResponseFact) -> Result<(), String> {
    if response.from_endpoint == [0; 32] {
        return Err("membership connection response from_endpoint cannot be empty".to_string());
    }
    if response.to_endpoint == [0; 32] {
        return Err("membership connection response to_endpoint cannot be empty".to_string());
    }
    if response.request_id == [0; 32] {
        return Err("membership connection response request_id cannot be empty".to_string());
    }
    if response.initiator_ephemeral_secret_fact_id == [0; 32] {
        return Err(
            "membership connection response initiator_ephemeral_secret_fact_id cannot be empty"
                .to_string(),
        );
    }
    if response.responder_ephemeral_secret_fact_id == [0; 32] {
        return Err(
            "membership connection response responder_ephemeral_secret_fact_id cannot be empty"
                .to_string(),
        );
    }
    if response.responder_ephemeral_public_key == [0; 32] {
        return Err(
            "membership connection response responder_ephemeral_public_key cannot be empty"
                .to_string(),
        );
    }
    if response.handshake_hash == [0; 32] {
        return Err("membership connection response handshake_hash cannot be empty".to_string());
    }
    if response.connection_secret == [0; 32] {
        return Err("membership connection response connection_secret cannot be empty".to_string());
    }
    Ok(())
}

fn validate_request_response(
    response: &ConnectionResponseFact,
    request: &request_family::fact::ConnectionRequestFact,
) -> Result<(), String> {
    if request.from_endpoint != response.to_endpoint {
        return Err("membership connection response references another endpoint's request".into());
    }
    if request.to_endpoint != response.from_endpoint {
        return Err("membership connection response sender does not match request recipient".into());
    }
    if response.initiator_ephemeral_secret_fact_id != request.initiator_ephemeral_secret_fact_id {
        return Err("membership connection response initiator ephemeral does not match request".into());
    }
    Ok(())
}

fn validate_fact_receipt(
    response_id: [u8; 32],
    response: &ConnectionResponseFact,
    received: &fact_receipt::fact::ConnectionFactReceipt,
) -> Result<(), String> {
    if received.received_fact_id != response_id {
        return Err("membership connection response receive context targets another fact".into());
    }
    if received.receive_path != RECEIVE_PATH_CONNECTION_RESPONSE {
        return Err("membership connection response requires connection response receipt".into());
    }
    if received.local_endpoint_id != response.to_endpoint {
        return Err("membership connection response addressed to a different endpoint".into());
    }
    if received.sender_endpoint_id != response.from_endpoint {
        return Err("membership connection response sender does not match receive sender".into());
    }
    if received.request_id != Some(response.request_id) {
        return Err("membership connection response fact receipt names another request".into());
    }
    if let Some(connection_id) = received.connection_id {
        if connection_id != response_id {
            return Err("membership connection response fact receipt names another connection".into());
        }
    }
    Ok(())
}

fn materialized_output(
    fact: &Fact,
    response: &ConnectionResponseFact,
    seed_sync: SeedSync,
) -> Result<ProjectionOutput, String> {
    let response_id = fact.id;
    let mut output = ProjectionOutput::new()
        .need(close::connection_closed_need(response_id, response_id))
        .offer(crate::core::context::ContextOffer::range(
            response_id,
            "connection_response",
            FactScope::Local,
            response_id,
            response_id,
        ))
        .offer(request_family::connection_response_for_request_offer(
            response_id,
            response.request_id,
        ))
        .row_mutation(RowMutation::PutRow(connection_row(ConnectionRowFields {
            connection_id: response_id,
            from_endpoint: response.from_endpoint,
            to_endpoint: response.to_endpoint,
            request_id: response.request_id,
            responder_ephemeral_public_key: response.responder_ephemeral_public_key,
            handshake_hash: response.handshake_hash,
            connection_secret: response.connection_secret,
        })?));
    if seed_sync == SeedSync::Immediate {
        output = output.intent(seed_connection_sync_intent(SeedConnectionSync {
            connection_id: response_id,
        }));
    }
    Ok(output)
}

fn closed_output(response_id: [u8; 32]) -> Result<ProjectionOutput, String> {
    Ok(ProjectionOutput::new()
        .row_mutation(RowMutation::DeleteRow(TableDelete {
            table: BOOTSTRAP_RESPONSE_ROWS,
            key: bootstrap_response_key(&response_id),
        }))
        .purge_self(response_id))
}

fn waiting_output<const N: usize>(
    needs: [crate::core::context::ContextNeed; N],
) -> ProjectionOutput {
    let mut output = ProjectionOutput::new();
    for need in needs {
        output = output.need(need);
    }
    output
}
