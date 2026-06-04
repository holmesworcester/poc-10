//! Unified connection projector.
//!
//! The same sealed connection fact is projected on both sides. The
//! responder can reopen it with the responder ephemeral secret and send it; the
//! initiator can reopen it with its local endpoint, pair it with the receive
//! observation, and seed sync.
//!
//! POLICY. A connection is admitted iff:
//!   1. STRUCTURAL. The local fact id matches sealed connection bytes whose
//!      header names an existing request.
//!   2. CONTEXT. Projection opens the request from local endpoint or initiator
//!      ephemeral context, validates bootstrap or membership authority, and then
//!      validates the connection handshake transcript from the available side.
//!   3. MATERIALIZE. Live connections write one connection row; close context
//!      deletes that row and purges the connection fact.

use crate::core::context::{ContextNeed, ContextOffer};
use crate::core::crypto;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::{RowMutation, TableDelete};
use crate::core::projectors::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, FactCodec, ProjectionContext,
    ProjectionOutput, Projector,
};
use crate::protocol::auth::{endpoint, invite};
use crate::protocol::connection::close;
use crate::protocol::connection::connection::rows::{
    connection_key, connection_row, ConnectionRowFields, CONNECTION_ROWS,
};
use crate::protocol::connection::ephemeral_secret;
use crate::protocol::connection::fact_receipt::fact::RECEIVE_PATH_CONNECTION;
use crate::protocol::connection::frame_observation;
use crate::protocol::connection::request;
use crate::protocol::connection::request::fact::{REQUEST_MODE_BOOTSTRAP, REQUEST_MODE_MEMBERSHIP};
use crate::protocol::connection::send_network_frame::{
    send_network_frame_intent, SendNetworkFrame,
};
use crate::protocol::connection_frame::{
    connection_fact_receipt_for_path, ConnectionFactReceiptInput,
};
use crate::protocol::sync::seed_connection::{seed_connection_sync_intent, SeedConnectionSync};

use super::create;
use super::fact::ConnectionFact;
use super::layout;

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
        project_authenticated::<super::authenticate::ConnectionAuthenticator, _>(
            self, fact, context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::ConnectionAuthenticator> for ConnectionProjector {
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, ()>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let (fact, ()) = authenticated.into_parts();
        // 1. Structural.
        if fact.scope != FactScope::Local {
            return Err("connection fact must have local scope".to_string());
        }
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

        // 2. Context.
        let request_id = layout::connection_header_request_id(fact.body())?;
        let request_need = request::project::connection_request_need(fact.id, request_id);
        let Some(request_fact) = context.payload_for(&request_need) else {
            return Ok(ProjectionOutput::new().need(close_need).need(request_need));
        };
        let request = match open_request_from_context(request_fact, context, fact.id) {
            Ok(request) => request,
            Err(_) => {
                return Ok(ProjectionOutput::new()
                    .need(close_need)
                    .need(request_need)
                    .need(all_local_endpoint_need(fact.id))
                    .need(all_ephemeral_secret_need(fact.id)));
            }
        };

        let responder_secret_need = all_ephemeral_secret_need(fact.id);
        for (_, secret_fact) in context.matched_payloads_for(&responder_secret_need) {
            if secret_fact.scope != FactScope::Local {
                return Err("connection responder secret context must be local".to_string());
            }
            let secret =
                ephemeral_secret::decode_fact_payload(secret_fact.body()).map_err(|_| {
                    "connection responder context is not an ephemeral secret".to_string()
                })?;
            let Ok(connection) = layout::open_fact_as_responder(fact.body(), &secret) else {
                continue;
            };
            validate_connection(fact.id, &connection, &request)?;
            if connection.responder_ephemeral_secret_fact_id != secret_fact.id {
                return Err("connection responder secret id does not match".to_string());
            }
            if let Some(invite_need) = bootstrap_invite_need(fact.id, &request) {
                if context.payload_for(&invite_need).is_none() {
                    return Ok(ProjectionOutput::new()
                        .need(close_need)
                        .need(request_need)
                        .need(responder_secret_need.clone())
                        .need(invite_need));
                }
            }
            validate_material(&connection, &request, context, fact.id, None)?;
            return Ok(materialized_output(fact, &connection, close_need)
                .need(request_need)
                .need(responder_secret_need.clone())
                .offer(request::project::connection_for_request_offer(
                    fact.id, request_id,
                ))
                .local_intent(send_network_frame_intent(SendNetworkFrame {
                    routing_key: fact.id,
                    frame: fact.body().to_vec(),
                })));
        }

        let endpoint_need = all_local_endpoint_need(fact.id);
        for (_, endpoint_fact) in context.matched_payloads_for(&endpoint_need) {
            if endpoint_fact.scope != FactScope::Local {
                return Err("connection endpoint context must be local".to_string());
            }
            let local_endpoint = endpoint::decode_fact_payload(endpoint_fact.body())
                .map_err(|_| "connection endpoint context is malformed".to_string())?;
            let Ok(connection) = layout::open_fact(fact.body(), &local_endpoint) else {
                continue;
            };
            validate_connection(fact.id, &connection, &request)?;
            let initiator_need = exact_need(
                fact.id,
                "connection_ephemeral_secret",
                FactScope::Local,
                connection.initiator_ephemeral_secret_fact_id,
            );
            let Some(initiator_fact) = context.payload_for(&initiator_need) else {
                return Ok(ProjectionOutput::new()
                    .need(close_need)
                    .need(request_need)
                    .need(endpoint_need.clone())
                    .need(initiator_need));
            };
            let initiator_secret = ephemeral_secret::decode_fact_payload(initiator_fact.body())
                .map_err(|_| {
                    "connection initiator context is not an ephemeral secret".to_string()
                })?;
            if let Some(invite_need) = bootstrap_invite_need(fact.id, &request) {
                if context.payload_for(&invite_need).is_none() {
                    return Ok(ProjectionOutput::new()
                        .need(close_need)
                        .need(request_need)
                        .need(endpoint_need.clone())
                        .need(initiator_need)
                        .need(invite_need));
                }
            }
            validate_material(
                &connection,
                &request,
                context,
                fact.id,
                Some(&initiator_secret),
            )?;
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
                    .need(endpoint_need.clone())
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
            return Ok(materialized_output(fact, &connection, close_need)
                .need(request_need)
                .need(endpoint_need.clone())
                .need(initiator_need)
                .need(observation_need)
                .fact(receipt)
                .intent(seed_connection_sync_intent(SeedConnectionSync {
                    connection_id: fact.id,
                })));
        }

        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .need(close_need)
            .need(request_need)
            .need(responder_secret_need)
            .need(endpoint_need))
    }
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

fn open_request_from_context(
    request_fact: &Fact,
    context: &ProjectionContext,
    owner: FactId,
) -> Result<request::fact::ConnectionRequestFact, String> {
    let endpoint_need = all_local_endpoint_need(owner);
    for (_, endpoint_fact) in context.matched_payloads_for(&endpoint_need) {
        if let Ok(endpoint) = endpoint::decode_fact_payload(endpoint_fact.body()) {
            if let Ok(request) = request::layout::open_fact(request_fact.body(), &endpoint) {
                return Ok(request);
            }
        }
    }
    let secret_need = all_ephemeral_secret_need(owner);
    for (_, secret_fact) in context.matched_payloads_for(&secret_need) {
        if let Ok(secret) = ephemeral_secret::decode_fact_payload(secret_fact.body()) {
            if let Ok(request) = request::layout::open_fact_as_sender(request_fact.body(), &secret)
            {
                return Ok(request);
            }
        }
    }
    Err("connection request context cannot be opened locally".to_string())
}

fn validate_connection(
    connection_id: FactId,
    connection: &ConnectionFact,
    request: &request::fact::ConnectionRequestFact,
) -> Result<(), String> {
    if connection_id == [0; 32] {
        return Err("connection id cannot be empty".to_string());
    }
    if connection.request_id == connection_id {
        return Err("connection cannot answer itself".to_string());
    }
    if request.from_endpoint != connection.to_endpoint {
        return Err("connection references another endpoint's request".to_string());
    }
    if request.to_endpoint != connection.from_endpoint {
        return Err("connection sender does not match request recipient".to_string());
    }
    if connection.initiator_ephemeral_secret_fact_id != request.initiator_ephemeral_secret_fact_id {
        return Err("connection initiator ephemeral does not match request".to_string());
    }
    if connection.responder_ephemeral_public_key == [0; 32] {
        return Err("connection responder ephemeral public key cannot be empty".to_string());
    }
    if connection.handshake_hash == [0; 32] || connection.connection_secret == [0; 32] {
        return Err("connection material cannot be empty".to_string());
    }
    Ok(())
}

fn validate_material(
    connection: &ConnectionFact,
    request: &request::fact::ConnectionRequestFact,
    context: &ProjectionContext,
    owner: FactId,
    initiator_secret: Option<&ephemeral_secret::fact::ConnectionEphemeralSecretFact>,
) -> Result<(), String> {
    let invite = match request.mode {
        REQUEST_MODE_BOOTSTRAP => {
            let need = exact_need(
                owner,
                "connection_invite_secret",
                FactScope::Local,
                request.invite_secret_fact_id,
            );
            let Some(fact) = context.payload_for(&need) else {
                return Err("connection bootstrap invite context is missing".to_string());
            };
            Some(
                invite::decode_fact_payload(fact.body())
                    .map_err(|_| "connection invite context is malformed".to_string())?,
            )
        }
        REQUEST_MODE_MEMBERSHIP => None,
        other => return Err(format!("unknown connection request mode {other}")),
    };
    if let Some(initiator_secret) = initiator_secret {
        let material = create::initiator_material(
            connection.request_id,
            request,
            invite.as_ref(),
            initiator_secret,
            &connection.responder_ephemeral_public_key,
            connection.responder_addr,
            connection.initiator_addr,
        )?;
        if material.handshake_hash != connection.handshake_hash
            || material.connection_secret != connection.connection_secret
        {
            return Err("connection material does not match initiator handshake".to_string());
        }
    } else if create::public_handshake_hash(
        connection.request_id,
        request,
        &connection.responder_ephemeral_public_key,
        connection.responder_addr,
        connection.initiator_addr,
    )? != connection.handshake_hash
    {
        return Err("connection handshake hash does not match transcript".to_string());
    }
    Ok(())
}

fn all_ephemeral_secret_need(owner: FactId) -> ContextNeed {
    ContextNeed::range(
        owner,
        "connection_ephemeral_secret",
        FactScope::Local,
        [0; 32],
        [0xff; 32],
    )
}

fn all_local_endpoint_need(owner: FactId) -> ContextNeed {
    ContextNeed::range(
        owner,
        "auth_local_endpoint",
        FactScope::Local,
        [0; 32],
        [0xff; 32],
    )
}

fn exact_need(owner: FactId, role: &'static str, scope: FactScope, key: FactId) -> ContextNeed {
    ContextNeed::range(owner, role, scope, key, key)
}

fn bootstrap_invite_need(
    owner: FactId,
    request: &request::fact::ConnectionRequestFact,
) -> Option<ContextNeed> {
    (request.mode == REQUEST_MODE_BOOTSTRAP).then(|| {
        exact_need(
            owner,
            "connection_invite_secret",
            FactScope::Local,
            request.invite_secret_fact_id,
        )
    })
}
