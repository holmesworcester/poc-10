//! Poc-10 connection-response projector.
//!
//! A response projects only after its exact request and invite-secret context
//! are present. Local responses additionally require the responder ephemeral
//! secret; received responses require transit receive provenance and the local
//! initiator ephemeral secret. Network and route effects stay in handlers.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::event_modules::connection_ephemeral_secret::{
    layout as ephemeral_layout, matchers as ephemeral_matchers,
};
use crate::event_modules::connection_request::{
    layout as request_layout, matchers as request_matchers,
};
use crate::event_modules::identity_invite::layout as invite_layout;
use crate::event_modules::transit_received::{
    fact::TRANSIT_KIND_CONNECTION_HANDSHAKE, layout as receive_layout, matchers as receive_matchers,
};

use super::create;
use super::fact::ConnectionResponseFact;
use super::layout;
use super::rows::connection_response_row;

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
        let response = layout::decode_fact(&fact.bytes)?;
        if response.from_endpoint == response.to_endpoint {
            return Err("connection response endpoints must differ".to_string());
        }
        if response.request_id == fact.id {
            return Err("connection response cannot answer itself".to_string());
        }

        let request_need = request_matchers::connection_request_need(fact.id, response.request_id);
        let Some(request_context) = projection_context.payload_for(&request_need) else {
            return Ok(waiting_output([request_need]));
        };
        let request = request_layout::decode_fact(&request_context.bytes)
            .map_err(|_| "connection response context is not a request fact".to_string())?;
        if request_context.id != response.request_id {
            return Err(
                "connection response request context id does not match response".to_string(),
            );
        }
        validate_request_response(&response, &request)?;

        let invite_need =
            request_matchers::invite_secret_need(fact.id, response.invite_secret_event_id);
        let Some(invite_context) = projection_context.payload_for(&invite_need) else {
            return Ok(waiting_output([request_need, invite_need]));
        };
        let invite = invite_layout::decode_fact(&invite_context.bytes).map_err(|_| {
            "connection response invite context is not an invite secret".to_string()
        })?;
        if invite_context.id != response.invite_secret_event_id {
            return Err(
                "connection response invite context id does not match response".to_string(),
            );
        }
        if invite.bootstrap_hash != request.bootstrap_hash {
            return Err("connection response invite secret does not match request".to_string());
        }
        if response.handshake_hash
            != create::public_handshake_hash(
                response.request_id,
                &request,
                &response.responder_ephemeral_public_key,
            )
        {
            return Err("connection response handshake hash does not match transcript".to_string());
        }

        let responder_ephemeral_need = ephemeral_matchers::connection_ephemeral_secret_need(
            fact.id,
            response.responder_ephemeral_secret_event_id,
        );
        let receive_need = receive_matchers::transit_received_need(fact.id, fact.id);

        if let Some(receive) = projection_context.payload_for(&receive_need) {
            if receive.scope != FactScope::Local {
                return Err("connection response receive context must be local".to_string());
            }
            let received = receive_layout::decode_fact(&receive.bytes).map_err(|_| {
                "connection response receive context is not transit provenance".to_string()
            })?;
            validate_receive_provenance(fact.id, &response, &received)?;
            let initiator_ephemeral_need = ephemeral_matchers::connection_ephemeral_secret_need(
                fact.id,
                response.initiator_ephemeral_secret_event_id,
            );
            let Some(initiator_ephemeral) =
                projection_context.payload_for(&initiator_ephemeral_need)
            else {
                return Ok(waiting_output([
                    request_need,
                    invite_need,
                    initiator_ephemeral_need,
                    receive_need,
                ]));
            };
            let initiator_secret = ephemeral_layout::decode_fact(&initiator_ephemeral.bytes)
                .map_err(|_| {
                    "connection response initiator dependency is not an ephemeral secret"
                        .to_string()
                })?;
            if initiator_ephemeral.id != response.initiator_ephemeral_secret_event_id {
                return Err(
                    "connection response initiator ephemeral context id does not match response"
                        .to_string(),
                );
            }
            let material = create::initiator_material(
                response.request_id,
                &request,
                &invite,
                &initiator_secret,
                &response.responder_ephemeral_public_key,
            )?;
            if response.connection_secret != material.connection_secret {
                return Err("connection response secret does not match handshake".to_string());
            }
            return materialized_output(fact.id, &response);
        }

        let Some(responder_ephemeral) = projection_context.payload_for(&responder_ephemeral_need)
        else {
            return Ok(waiting_output([
                request_need,
                invite_need,
                responder_ephemeral_need,
                receive_need,
            ]));
        };
        let responder_secret =
            ephemeral_layout::decode_fact(&responder_ephemeral.bytes).map_err(|_| {
                "connection response responder dependency is not an ephemeral secret".to_string()
            })?;
        if responder_ephemeral.id != response.responder_ephemeral_secret_event_id {
            return Err(
                "connection response responder ephemeral context id does not match response"
                    .to_string(),
            );
        }
        if responder_secret.owner_endpoint != response.from_endpoint {
            return Err(
                "connection response responder ephemeral owner does not match sender".to_string(),
            );
        }
        if responder_secret.ephemeral_public_key != response.responder_ephemeral_public_key {
            return Err(
                "connection response responder ephemeral public key does not match dependency"
                    .to_string(),
            );
        }
        materialized_output(fact.id, &response)
    }
}

fn validate_request_response(
    response: &ConnectionResponseFact,
    request: &crate::event_modules::connection_request::fact::ConnectionRequestFact,
) -> Result<(), String> {
    if request.from_endpoint != response.to_endpoint {
        return Err("connection response references another endpoint's request".to_string());
    }
    if request.to_endpoint != response.from_endpoint {
        return Err("connection response sender does not match request recipient".to_string());
    }
    if response.invite_secret_event_id != request.invite_secret_event_id {
        return Err("connection response invite dependency does not match request".to_string());
    }
    if response.initiator_ephemeral_secret_event_id != request.initiator_ephemeral_secret_event_id {
        return Err("connection response initiator ephemeral does not match request".to_string());
    }
    Ok(())
}

fn validate_receive_provenance(
    response_id: [u8; 32],
    response: &ConnectionResponseFact,
    received: &crate::event_modules::transit_received::fact::TransitReceivedFact,
) -> Result<(), String> {
    if received.received_fact_id != response_id {
        return Err("connection response receive context targets another fact".to_string());
    }
    if received.transit_kind != TRANSIT_KIND_CONNECTION_HANDSHAKE {
        return Err("connection response requires handshake receive provenance".to_string());
    }
    if received.local_endpoint_id != response.to_endpoint {
        return Err("connection response addressed to a different endpoint".to_string());
    }
    if received.sender_endpoint_id != response.from_endpoint {
        return Err("connection response sender does not match receive sender".to_string());
    }
    if received.request_id != Some(response.request_id) {
        return Err("connection response receive provenance names another request".to_string());
    }
    if let Some(connection_id) = received.connection_id {
        if connection_id != response_id {
            return Err(
                "connection response receive provenance names another connection".to_string(),
            );
        }
    }
    Ok(())
}

fn materialized_output(
    response_id: [u8; 32],
    response: &ConnectionResponseFact,
) -> Result<ProjectionOutput, String> {
    Ok(ProjectionOutput::new().intent(
        AtomicIntent::PutRow(connection_response_row(response_id, response)?).into_intent(),
    ))
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
