//! Unified connection projector.
//!
//! The same sealed connection fact is projected on both sides after
//! `authenticate.rs` has resolved the request, opened the sealed connection, and
//! verified handshake material. The responder branch sends the connection fact;
//! the initiator branch pairs it with the receive observation and seeds sync.
//! During replay this live session state is intentionally not rebuilt; the
//! retained fact remains evidence, but the projector returns no effects.
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
use crate::core::pipeline::{FactPipeline, ProjectionContext, ProjectionOutput, Projector};
use crate::protocol::connection::close;
use crate::protocol::connection::connection::{
    connection_key, connection_row, ConnectionRowFields, CONNECTION_ROWS,
};
use crate::protocol::connection::fact_receipt::fact::ReceiptPathInput;
use crate::protocol::connection::fact_receipt::fact::RECEIVE_PATH_CONNECTION;
use crate::protocol::connection::fact_receipt::project::connection_fact_receipt_for_path;
use crate::protocol::connection::frame_observation;
use crate::protocol::connection::request;
use crate::protocol::connection::send_network_frame::{
    send_network_frame_intent, SendNetworkFrame,
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

/// Projector route metadata for the connection fact.
pub const PIPELINE: FactPipeline =
    FactPipeline::projector("connection::connection::project::ConnectionProjector");

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
        super::decode::validate_sealed_fact(fact.body())?;
        match super::authenticate::authenticate(fact, context)? {
            authenticate::Authentication::Authenticated(authenticated) => {
                let semantic = super::adapt::adapt(authenticated)?;
                self.project_semantic(fact, semantic, context)
            }
            authenticate::Authentication::NeedsContext(needs) => Ok(needs
                .into_iter()
                .fold(ProjectionOutput::new(), |output, need| output.need(need))),
        }
    }
}

impl ConnectionProjector {
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
        if context.is_replay() {
            return Ok(ProjectionOutput::new());
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
                request_opener_need,
                responder_secret_need,
                invite_need,
            } => {
                let needs = ConnectionNeeds::responder(
                    close_need,
                    request_need,
                    request_opener_need,
                    responder_secret_need,
                    invite_need,
                );
                let output = needs.apply_to(materialized_output(fact, &connection));
                Ok(output
                    .offer(request::project::connection_for_request_offer(
                        fact.id,
                        connection.request_id,
                    ))
                    .intent(seed_connection_sync_intent(SeedConnectionSync {
                        connection_id: fact.id,
                    }))
                    .local_intent(send_network_frame_intent(SendNetworkFrame {
                        routing_key: fact.id,
                        frame: fact.body().to_vec(),
                    })))
            }
            AuthenticatedConnection::Initiator {
                connection,
                request_need,
                request_opener_need,
                endpoint_need,
                initiator_need,
                invite_need,
            } => project_initiator_connection(
                fact,
                &connection,
                context,
                ConnectionNeeds::initiator(
                    close_need,
                    request_need,
                    request_opener_need,
                    endpoint_need,
                    initiator_need,
                    invite_need,
                ),
            ),
        }
    }
}

fn project_initiator_connection(
    fact: &Fact,
    connection: &ConnectionFact,
    context: &ProjectionContext,
    needs: ConnectionNeeds,
) -> Result<ProjectionOutput, String> {
    let observation_need = exact_need(
        fact.id,
        "connection_frame_observation",
        FactScope::Local,
        fact.id,
    );
    let needs = needs.with_observation(observation_need.clone());
    let Some(observation_fact) = context.payload_for(&observation_need) else {
        return Ok(needs.apply_to(ProjectionOutput::new()));
    };
    let observation = frame_observation::decode::decode_fact(observation_fact.body())
        .map_err(|_| "connection observation context is malformed".to_string())?;
    if observation.frame_fact_id != fact.id {
        return Err("connection observation targets another fact".to_string());
    }
    let receipt = connection_fact_receipt_for_path(ReceiptPathInput {
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
    Ok(needs
        .apply_to(materialized_output(fact, connection))
        .fact(receipt)
        .intent(seed_connection_sync_intent(SeedConnectionSync {
            connection_id: fact.id,
        })))
}

fn materialized_output(fact: &Fact, connection: &ConnectionFact) -> ProjectionOutput {
    ProjectionOutput::new()
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

#[derive(Debug, Clone)]
struct ConnectionNeeds {
    close: ContextNeed,
    request: ContextNeed,
    request_opener: ContextNeed,
    responder_secret: Option<ContextNeed>,
    endpoint: Option<ContextNeed>,
    initiator: Option<ContextNeed>,
    observation: Option<ContextNeed>,
    invite: Option<ContextNeed>,
}

impl ConnectionNeeds {
    fn responder(
        close: ContextNeed,
        request: ContextNeed,
        request_opener: ContextNeed,
        responder_secret: ContextNeed,
        invite: Option<ContextNeed>,
    ) -> Self {
        Self {
            close,
            request,
            request_opener,
            responder_secret: Some(responder_secret),
            endpoint: None,
            initiator: None,
            observation: None,
            invite,
        }
    }

    fn initiator(
        close: ContextNeed,
        request: ContextNeed,
        request_opener: ContextNeed,
        endpoint: ContextNeed,
        initiator: ContextNeed,
        invite: Option<ContextNeed>,
    ) -> Self {
        Self {
            close,
            request,
            request_opener,
            responder_secret: None,
            endpoint: Some(endpoint),
            initiator: Some(initiator),
            observation: None,
            invite,
        }
    }

    fn with_observation(mut self, observation: ContextNeed) -> Self {
        self.observation = Some(observation);
        self
    }

    fn apply_to(&self, output: ProjectionOutput) -> ProjectionOutput {
        let mut output = output
            .need(self.close.clone())
            .need(self.request.clone())
            .need(self.request_opener.clone());
        for need in [
            &self.responder_secret,
            &self.endpoint,
            &self.initiator,
            &self.observation,
            &self.invite,
        ]
        .into_iter()
        .flatten()
        {
            output = output.need(need.clone());
        }
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::pipeline::ProjectionMode;
    use crate::protocol::connection::send_network_frame::SEND_NETWORK_FRAME;
    use crate::protocol::sync::seed_connection::SEED_CONNECTION_SYNC;

    fn connection_fact() -> ConnectionFact {
        ConnectionFact {
            from_endpoint: [1; 32],
            to_endpoint: [2; 32],
            request_id: [3; 32],
            responder_addr: None,
            initiator_addr: None,
            initiator_ephemeral_secret_fact_id: [4; 32],
            responder_ephemeral_secret_fact_id: [5; 32],
            responder_ephemeral_public_key: [6; 32],
            handshake_hash: [7; 32],
            connection_secret: [8; 32],
        }
    }

    #[test]
    fn responder_projection_sends_response_and_seeds_sync() {
        let fact = Fact::new(FactScope::Local, 10, vec![49, 1, 2, 3]);
        let request_need = request::project::connection_request_need(fact.id, [3; 32]);
        let request_opener_need = authenticate::all_local_endpoint_need(fact.id);
        let responder_secret_need = authenticate::all_ephemeral_secret_need(fact.id);
        let invite_need = authenticate::exact_need(
            fact.id,
            "connection_invite_secret",
            FactScope::Local,
            [9; 32],
        );

        let output = ConnectionProjector::new()
            .project_semantic(
                &fact,
                AuthenticatedConnection::Responder {
                    connection: connection_fact(),
                    request_need,
                    request_opener_need,
                    responder_secret_need,
                    invite_need: Some(invite_need),
                },
                &ProjectionContext::default(),
            )
            .expect("project responder connection");

        assert!(output
            .needs
            .iter()
            .any(|need| need.role.as_str() == "connection_invite_secret"));
        assert!(output
            .effects
            .intents
            .iter()
            .any(|intent| intent.kind.as_str() == SEED_CONNECTION_SYNC));
        assert!(output
            .effects
            .local_intents
            .iter()
            .any(|intent| intent.kind.as_str() == SEND_NETWORK_FRAME));
    }

    #[test]
    fn replay_projection_does_not_rebuild_live_connection_state() {
        let fact = Fact::new(FactScope::Local, 10, vec![49, 1, 2, 3]);
        let output = ConnectionProjector::new()
            .project_semantic(
                &fact,
                AuthenticatedConnection::Responder {
                    connection: connection_fact(),
                    request_need: request::project::connection_request_need(fact.id, [3; 32]),
                    request_opener_need: authenticate::all_local_endpoint_need(fact.id),
                    responder_secret_need: authenticate::all_ephemeral_secret_need(fact.id),
                    invite_need: None,
                },
                &ProjectionContext::default().with_mode(ProjectionMode::Replay),
            )
            .expect("replay connection");

        assert!(output.offers.is_empty());
        assert!(output.needs.is_empty());
        assert!(output.effects.row_mutations.is_empty());
        assert!(output.effects.intents.is_empty());
        assert!(output.effects.local_intents.is_empty());
    }
}
