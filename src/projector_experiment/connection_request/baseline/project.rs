//! Poc-10 connection-request projector.
//!
//! A request can be local bootstrap work or a received bootstrap request. Both
//! branches validate the canonical body and exact invite-secret context first.
//! Local requests additionally require the named local initiator ephemeral
//! secret; received requests require exact transit receive provenance instead.
//! Network attempt/response effects stay in handlers.

use crate::core::crypto;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use crate::event_modules::connection_ephemeral_secret::{
    layout as ephemeral_layout, matchers as ephemeral_matchers,
};
use crate::event_modules::identity_invite::layout as invite_layout;
use crate::event_modules::transit_received::{
    layout as receive_layout, matchers as receive_matchers,
};

use crate::event_modules::connection_request::addr::encode_optional_addr;
use crate::event_modules::connection_request::fact::ConnectionRequestFact;
use crate::event_modules::connection_request::layout;
use crate::event_modules::connection_request::matchers;
use crate::event_modules::connection_request::rows::connection_request_row;

#[derive(Debug, Clone, Default)]
pub struct ConnectionRequestProjector;

impl ConnectionRequestProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionRequestProjector {
    fn project(
        &self,
        fact: &Fact,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if !matches!(fact.scope, FactScope::Local | FactScope::Global) {
            return Err("connection request fact must be local or global".to_string());
        }
        let request = layout::decode_fact(&fact.bytes)?;
        validate_request_fields(&request)?;
        if request.from_endpoint == request.to_endpoint {
            return Err("connection request endpoints must differ".to_string());
        }

        let invite_need = matchers::invite_secret_need(fact.id, request.invite_secret_event_id);
        let Some(invite) = projection_context.payload_for(&invite_need) else {
            return Ok(waiting_output([invite_need]));
        };
        let invite_secret = invite_layout::decode_fact(&invite.bytes)
            .map_err(|_| "connection request invite context is not an invite secret".to_string())?;
        if invite.id != request.invite_secret_event_id {
            return Err("connection request invite context id does not match request".to_string());
        }
        if invite.scope != FactScope::Local {
            return Err("connection request invite context must be local".to_string());
        }
        validate_invite_signature(&request, &invite_secret)?;

        if fact.scope == FactScope::Local {
            let ephemeral_need = ephemeral_matchers::connection_ephemeral_secret_need(
                fact.id,
                request.initiator_ephemeral_secret_event_id,
            );
            let Some(ephemeral) = projection_context.payload_for(&ephemeral_need) else {
                return Ok(waiting_output([invite_need, ephemeral_need]));
            };
            let ephemeral_secret =
                ephemeral_layout::decode_fact(&ephemeral.bytes).map_err(|_| {
                    "connection request dependency is not an ephemeral secret".to_string()
                })?;
            if ephemeral.id != request.initiator_ephemeral_secret_event_id {
                return Err(
                    "connection request ephemeral context id does not match request".to_string(),
                );
            }
            if ephemeral.scope != FactScope::Local {
                return Err("connection request ephemeral context must be local".to_string());
            }
            if ephemeral_secret.owner_endpoint != request.from_endpoint {
                return Err("connection request ephemeral owner does not match sender".to_string());
            }
            if ephemeral_secret.ephemeral_public_key != request.initiator_ephemeral_public_key {
                return Err(
                    "connection request ephemeral public key does not match dependency".to_string(),
                );
            }
            return materialized_output(fact.id, &request);
        }

        let receive_need = receive_matchers::transit_received_need(fact.id, fact.id);
        let Some(receive) = projection_context.payload_for(&receive_need) else {
            return Ok(waiting_output([invite_need, receive_need]));
        };
        if receive.scope != FactScope::Local {
            return Err("connection request receive context must be local".to_string());
        }
        let received = receive_layout::decode_fact(&receive.bytes).map_err(|_| {
            "connection request receive context is not transit provenance".to_string()
        })?;
        if received.received_fact_id != fact.id {
            return Err("connection request receive context targets another fact".to_string());
        }
        if received.transit_kind
            != crate::event_modules::transit_received::fact::TRANSIT_KIND_BOOTSTRAP
        {
            return Err("connection request requires bootstrap receive provenance".to_string());
        }
        if received.local_endpoint_id != request.to_endpoint {
            return Err("connection request addressed to a different endpoint".to_string());
        }
        if received.sender_endpoint_id != request.from_endpoint {
            return Err("connection request sender does not match receive sender".to_string());
        }
        if let Some(request_id) = received.request_id {
            if request_id != fact.id {
                return Err(
                    "connection request receive provenance names another request".to_string(),
                );
            }
        }

        materialized_output(fact.id, &request)
    }
}

fn validate_request_fields(request: &ConnectionRequestFact) -> Result<(), String> {
    if request.from_endpoint == [0; 32] {
        return Err("connection request from_endpoint cannot be empty".to_string());
    }
    if request.to_endpoint == [0; 32] {
        return Err("connection request to_endpoint cannot be empty".to_string());
    }
    if request.invite_event_id == [0; 32] {
        return Err("connection request invite_event_id cannot be empty".to_string());
    }
    if request.bootstrap_hash == [0; 32] {
        return Err("connection request bootstrap_hash cannot be empty".to_string());
    }
    if request.invite_secret_event_id == [0; 32] {
        return Err("connection request invite_secret_event_id cannot be empty".to_string());
    }
    if request.initiator_ephemeral_secret_event_id == [0; 32] {
        return Err(
            "connection request initiator_ephemeral_secret_event_id cannot be empty".to_string(),
        );
    }
    if request.initiator_ephemeral_public_key == [0; 32] {
        return Err(
            "connection request initiator_ephemeral_public_key cannot be empty".to_string(),
        );
    }
    Ok(())
}

fn materialized_output(
    request_id: [u8; 32],
    request: &ConnectionRequestFact,
) -> Result<ProjectionOutput, String> {
    Ok(ProjectionOutput::new()
        .offer(matchers::connection_request_offer(request_id, request_id))
        .intent(AtomicIntent::PutRow(connection_request_row(request_id, request)?).into_intent()))
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

fn validate_invite_signature(
    request: &ConnectionRequestFact,
    invite_secret: &crate::event_modules::identity_invite::fact::InviteSecretFact,
) -> Result<(), String> {
    if invite_secret.bootstrap_hash != request.bootstrap_hash {
        return Err("connection request bootstrap hash is not authorized".to_string());
    }
    if let Some(invite_event_id) = invite_secret.invite_event_id {
        if invite_event_id != request.invite_event_id {
            return Err("connection request invite id is not authorized".to_string());
        }
    }
    let public_key = crypto::ed25519_public_key(&invite_secret.bootstrap_secret);
    if !crypto::ed25519_verify(
        &public_key,
        &invite_signing_transcript(request)?,
        &request.invite_signature,
    ) {
        return Err("connection request invite signature is not authorized".to_string());
    }
    Ok(())
}

fn invite_signing_transcript(request: &ConnectionRequestFact) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    out.extend_from_slice(b"topo-connection-request-invite-signing-transcript-v1");
    out.extend_from_slice(&request.from_endpoint);
    out.extend_from_slice(&request.to_endpoint);
    out.extend_from_slice(&request.nonce);
    out.extend_from_slice(&request.invite_event_id);
    out.extend_from_slice(&request.bootstrap_hash);
    out.extend_from_slice(&request.invite_secret_event_id);
    out.extend_from_slice(&request.initiator_ephemeral_secret_event_id);
    out.extend_from_slice(&request.initiator_ephemeral_public_key);
    out.extend_from_slice(&encode_optional_addr(request.from_listen_addr)?);
    out.extend_from_slice(&encode_optional_addr(request.to_listen_addr)?);
    Ok(out)
}

