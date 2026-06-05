//! Unified connection projector.
//!
//! The same sealed connection fact is projected on both sides after
//! `authenticate.rs` has resolved the request, opened the sealed connection, and
//! verified handshake material. The responder branch sends the connection fact;
//! the initiator branch pairs it with the receive observation and seeds sync.
//!
//! POLICY. A connection is admitted iff:
//!   1. STRUCTURAL. The fact is local; primary byte shape, id, request opening,
//!      connection opening, and handshake material have already been
//!      authenticated.
//!   2. CONTEXT. Projection observes close and receive-observation context.
//!   3. MATERIALIZE. Live connections write one connection row; close context
//!      deletes that row and purges the connection fact.

use crate::core::context::{ContextNeed, ContextOffer};
use crate::core::crypto;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::{RowMutation, TableDelete};
use crate::core::pipeline::{
    project_staged, FactCodec, FactPipeline, ProjectionContext, ProjectionOutput, Projector,
    SemanticProjector,
};
use crate::protocol::connection::close;
use crate::protocol::connection::connection::{
    connection_key, connection_row, ConnectionRowFields, CONNECTION_ROWS,
};
use crate::protocol::connection::fact_receipt::fact::RECEIVE_PATH_CONNECTION;
use crate::protocol::connection::frame_observation;
use crate::protocol::connection::request;
use crate::protocol::connection::send_network_frame::{
    send_network_frame_intent, SendNetworkFrame,
};
use crate::protocol::connection_frame::{
    connection_fact_receipt_for_path, ConnectionFactReceiptInput,
};
use crate::protocol::sync::seed_connection::{seed_connection_sync_intent, SeedConnectionSync};

use super::authenticate::{self, AuthenticatedConnection};
use super::fact::ConnectionFact;

const CONNECTION_ROLE: &str = "connection";

pub fn connection_need(owner: FactId, connection_id: FactId) -> ContextNeed {
    ContextNeed::range(
        owner,
        CONNECTION_ROLE,
        FactScope::Local,
        connection_id,
        connection_id,
    )
}

pub fn connection_offer(owner: FactId, connection_id: FactId) -> ContextOffer {
    ContextOffer::range(
        owner,
        CONNECTION_ROLE,
        FactScope::Local,
        connection_id,
        connection_id,
    )
}

/// Staged read pipeline for the connection fact.
pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "connection::connection::Codec",
    authenticate: "connection::connection::authenticate::ConnectionAuthenticator",
    adapt: "connection::connection::adapt::ConnectionAdapter",
    project: "connection::connection::project::ConnectionProjector",
};

#[derive(Debug, Clone, Default)]
pub struct ConnectionProjector;

impl ConnectionProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_staged::<
            super::Codec,
            super::authenticate::ConnectionAuthenticator,
            super::adapt::ConnectionAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<AuthenticatedConnection> for ConnectionProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        semantic: AuthenticatedConnection,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Local {
            return Err("connection fact must have local scope".to_string());
        }
        // 2. Context.
        let close_need = close::connection_closed_need(fact.id, fact.id);
        if let Some(close_fact) = context.payload_for(&close_need) {
            if close_fact.scope != FactScope::Local {
                return Err("connection close context must be local".to_string());
            }
            return Ok(ProjectionOutput::new()
                .row_mutation(RowMutation::DeleteRow(TableDelete {
                    table: CONNECTION_ROWS,
                    key: connection_key(&fact.id),
                }))
                .purge_self(fact.id));
        }

        // 3. Materialize.
        match semantic {
            AuthenticatedConnection::Responder {
                connection,
                request_need,
                responder_secret_need,
            } => Ok(materialized_output(fact, &connection, close_need)
                .need(request_need)
                .need(responder_secret_need)
                .offer(request::project::connection_for_request_offer(
                    fact.id,
                    connection.request_id,
                ))
                .local_intent(send_network_frame_intent(SendNetworkFrame {
                    routing_key: fact.id,
                    frame: fact.body().to_vec(),
                }))),
            AuthenticatedConnection::Initiator {
                connection,
                request_need,
                endpoint_need,
                initiator_need,
            } => project_initiator_connection(
                fact,
                &connection,
                context,
                close_need,
                request_need,
                endpoint_need,
                initiator_need,
            ),
        }
    }
}

fn project_initiator_connection(
    fact: &Fact,
    connection: &ConnectionFact,
    context: &ProjectionContext,
    close_need: ContextNeed,
    request_need: ContextNeed,
    endpoint_need: ContextNeed,
    initiator_need: ContextNeed,
) -> Result<ProjectionOutput, String> {
    let observation_need = exact_need(
        fact.id,
        "connection_frame_observation",
        FactScope::Local,
        fact.id,
    );
    let Some(observation_fact) = context.payload_for(&observation_need) else {
        return Ok(ProjectionOutput::new()
            .need(close_need)
            .need(request_need)
            .need(endpoint_need)
            .need(initiator_need)
            .need(observation_need));
    };
    let observation = frame_observation::Codec::decode_fact(observation_fact)
        .map_err(|_| "connection observation context is malformed".to_string())?;
    if observation.frame_fact_id != fact.id {
        return Err("connection observation targets another fact".to_string());
    }
    let receipt = connection_fact_receipt_for_path(ConnectionFactReceiptInput {
        received_fact_id: fact.id,
        origin_addr: observation.origin_addr.bytes(),
        local_endpoint_id: connection.to_endpoint,
        sender_endpoint_id: connection.from_endpoint,
        receive_path: RECEIVE_PATH_CONNECTION,
        connection_id: Some(fact.id),
        request_id: Some(connection.request_id),
        frame_hash: crypto::hash(fact.body()),
        received_at_local_ms: observation.received_at_local_ms,
    })?;
    Ok(materialized_output(fact, connection, close_need)
        .need(request_need)
        .need(endpoint_need)
        .need(initiator_need)
        .need(observation_need)
        .fact(receipt)
        .intent(seed_connection_sync_intent(SeedConnectionSync {
            connection_id: fact.id,
        })))
}

fn materialized_output(
    fact: &Fact,
    connection: &ConnectionFact,
    close_need: ContextNeed,
) -> ProjectionOutput {
    ProjectionOutput::new()
        .need(close_need)
        .offer(connection_offer(fact.id, fact.id))
        .row_mutation(RowMutation::PutRow(
            connection_row(ConnectionRowFields {
                connection_id: fact.id,
                from_endpoint: connection.from_endpoint,
                to_endpoint: connection.to_endpoint,
                request_id: connection.request_id,
                responder_ephemeral_public_key: connection.responder_ephemeral_public_key,
                handshake_hash: connection.handshake_hash,
                connection_secret: connection.connection_secret,
                responder_addr: connection.responder_addr,
                initiator_addr: connection.initiator_addr,
            })
            .expect("connection row encodes"),
        ))
}

fn exact_need(owner: FactId, role: &'static str, scope: FactScope, key: FactId) -> ContextNeed {
    authenticate::exact_need(owner, role, scope, key)
}
