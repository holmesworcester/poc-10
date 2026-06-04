//! Membership connection-response projector.
//!
//! Response projection turns a received membership handshake answer into local
//! connection state. It proves exact local `connection_request_sent` context,
//! the initiator ephemeral secret, and the socket observation, then recomputes
//! the Diffie-Hellman handshake and emits `connection_response_received` plus a
//! symmetric `connection_established` fact.
//!
//! The materialized row is written into the shared connection table keyed by
//! connection id, identical to bootstrap connections, so established frames and
//! sync are agnostic to how the connection was authorized.
//!
//! POLICY. A connection_response is admitted iff:
//!   1. STRUCTURAL. The received sealed fact is local-only, response fields are non-empty, and
//!      the response references a different request fact.
//!   2. CONTEXT. Projection validates exact request-sent context, the socket
//!      observation, and the local initiator secret.
//!   3. MATERIALIZE. Valid responses emit response-received history,
//!      connection-established state, and seed the initial sync.
//!
//! Change this projector for membership response admission and sync seeding.
//! Byte layout lives in `layout.rs`; key-schedule construction in `create.rs`.

use crate::core::facts::{Fact, FactScope};
use crate::core::projectors::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, FactCodec, ProjectionContext,
    ProjectionOutput, Projector,
};

use crate::protocol::connection::connection_established;
use crate::protocol::connection::connection_established::fact::ConnectionEstablishedFact;
use crate::protocol::connection::connection_response_received;
use crate::protocol::connection::connection_response_received::fact::ConnectionResponseReceivedFact;
use crate::protocol::connection::ephemeral_secret;
use crate::protocol::connection::fact_receipt::fact::RECEIVE_PATH_CONNECTION_RESPONSE;
use crate::protocol::connection::frame_observation;
use crate::protocol::connection::{
    connection_request, connection_request_sent as request_sent_family,
};
use crate::protocol::connection_frame::{
    connection_fact_receipt_for_path, ConnectionFactReceiptInput,
};
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
        project_authenticated::<super::authenticate::ConnectionResponseAuthenticator, _>(
            self,
            fact,
            projection_context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::ConnectionResponseAuthenticator>
    for ConnectionResponseProjector
{
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, ConnectionResponseFact>,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // Authentication (see authenticate.rs) proved canonical bytes and the
        // intrinsic response fields. Scope is interpretation.
        let (fact, response) = authenticated.into_parts();
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("membership connection response fact must have local scope".to_string());
        }

        // 2. Local request-sent context.
        let request_need = request_sent_family::project::connection_request_sent_need(
            fact.id,
            response.request_id,
        );
        let Some(request_context) = projection_context.payload_for(&request_need) else {
            return Ok(waiting_output([request_need]));
        };
        if request_context.scope != FactScope::Local {
            return Err("membership connection response request-sent context must be local".into());
        }
        let sent =
            request_sent_family::decode_fact_payload(request_context.body()).map_err(|_| {
                "membership connection response context is not connection_request_sent".to_string()
            })?;
        let request = sent.request;
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

        let observation_need = crate::core::context::ContextNeed::range(
            fact.id,
            "connection_frame_observation",
            FactScope::Local,
            fact.id,
            fact.id,
        );
        let Some(observation_fact) = projection_context.payload_for(&observation_need) else {
            return Ok(waiting_output([request_need, observation_need]));
        };
        let observation =
            frame_observation::Codec::decode_fact(observation_fact).map_err(|_| {
                "membership connection response observation context is malformed".to_string()
            })?;
        if observation.frame_fact_id != fact.id {
            return Err("membership connection response observation targets another fact".into());
        }

        let initiator_ephemeral_need =
            ephemeral_need(fact.id, response.initiator_ephemeral_secret_fact_id);
        let Some(initiator_ephemeral) = projection_context.payload_for(&initiator_ephemeral_need)
        else {
            return Ok(waiting_output([
                request_need,
                observation_need,
                initiator_ephemeral_need,
            ]));
        };
        let initiator_secret = ephemeral_secret::decode_fact_payload(initiator_ephemeral.body())
            .map_err(|_| {
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
        materialized_output(
            fact,
            &response,
            observation.origin_addr.bytes(),
            crate::core::crypto::hash(fact.body()),
            observation.received_at_local_ms,
        )
    }
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

fn validate_request_response(
    response: &ConnectionResponseFact,
    request: &connection_request::fact::ConnectionRequestFact,
) -> Result<(), String> {
    if request.from_endpoint != response.to_endpoint {
        return Err("membership connection response references another endpoint's request".into());
    }
    if request.to_endpoint != response.from_endpoint {
        return Err(
            "membership connection response sender does not match request recipient".into(),
        );
    }
    if response.initiator_ephemeral_secret_fact_id != request.initiator_ephemeral_secret_fact_id {
        return Err(
            "membership connection response initiator ephemeral does not match request".into(),
        );
    }
    Ok(())
}

fn materialized_output(
    fact: &Fact,
    response: &ConnectionResponseFact,
    origin_addr: &[u8],
    frame_hash: [u8; 32],
    received_at_local_ms: u64,
) -> Result<ProjectionOutput, String> {
    let response_id = fact.id;
    let receipt = connection_fact_receipt_for_path(ConnectionFactReceiptInput {
        received_fact_id: response_id,
        origin_addr,
        local_endpoint_id: response.to_endpoint,
        sender_endpoint_id: response.from_endpoint,
        receive_path: RECEIVE_PATH_CONNECTION_RESPONSE,
        connection_id: Some(response_id),
        request_id: Some(response.request_id),
        frame_hash,
        received_at_local_ms,
    })?;
    let response_received = crate::core::facts::Fact::new(
        FactScope::Local,
        received_at_local_ms,
        connection_response_received::layout::encode_fact(&ConnectionResponseReceivedFact {
            response_id,
            request_id: response.request_id,
            receive_id: receipt.id,
            received_at_local_ms,
        })?,
    );
    let established = crate::core::facts::Fact::new(
        FactScope::Local,
        received_at_local_ms,
        connection_established::layout::encode_fact(&ConnectionEstablishedFact {
            connection_id: response_id,
            from_endpoint: response.from_endpoint,
            to_endpoint: response.to_endpoint,
            request_id: response.request_id,
            initiator_ephemeral_secret_fact_id: response.initiator_ephemeral_secret_fact_id,
            responder_ephemeral_secret_fact_id: response.responder_ephemeral_secret_fact_id,
            responder_ephemeral_public_key: response.responder_ephemeral_public_key,
            handshake_hash: response.handshake_hash,
            connection_secret: response.connection_secret,
            established_at_ms: received_at_local_ms,
        })?,
    );
    Ok(ProjectionOutput::new()
        .fact(receipt)
        .fact(response_received)
        .fact(established)
        .intent(seed_connection_sync_intent(SeedConnectionSync {
            connection_id: response_id,
        })))
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
