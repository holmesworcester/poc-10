//! Unified connection-request projector.
//!
//! The same sealed request fact is projected on both sides after
//! `authenticate.rs` has opened it with local sender/receiver context and
//! verified the bootstrap or membership signature. The initiator branch
//! materializes retryable send state. The responder branch records the receive
//! receipt and schedules `create_connection`. During replay this live
//! negotiation state is intentionally not rebuilt; the retained fact remains
//! evidence, but the projector returns no effects.
//!
//! POLICY. A connection_request is admitted iff:
//!   1. STRUCTURAL. The fact is global; primary byte shape, id, opening, and
//!      request signature have already been authenticated.
//!   2. CONTEXT. The initiator branch requires invite or endpoint_shared
//!      authority; the responder branch requires receive observation and
//!      matching authority context.
//!   3. MATERIALIZE. Initiators write retryable request send state; responders
//!      emit a receipt and the deterministic create_connection intent.

use crate::core::context::{ContextNeed, ContextOffer};
use crate::core::crypto;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::RowMutation;
use crate::core::pipeline::{
    project_staged, FactCodec, FactPipeline, ProjectionContext, ProjectionOutput, Projector,
    SemanticProjector,
};

use crate::protocol::auth::{endpoint_shared, invite, workspace};
use crate::protocol::connection::create_connection::{create_connection_intent, CreateConnection};
use crate::protocol::connection::frame_observation;
use crate::protocol::connection_frame::{
    connection_fact_receipt_for_path, ConnectionFactReceiptInput,
};

use super::authenticate;
use super::authenticate::AuthenticatedConnectionRequest;
use super::connection_request_row;
use super::fact::{ConnectionRequestFact, REQUEST_MODE_BOOTSTRAP, REQUEST_MODE_MEMBERSHIP};

const CONNECTION_REQUEST_ROLE: &str = "connection_request";
const CONNECTION_FOR_REQUEST_ROLE: &str = "connection_for_request";

pub fn connection_request_need(owner: FactId, request_id: FactId) -> ContextNeed {
    ContextNeed::range(
        owner,
        CONNECTION_REQUEST_ROLE,
        FactScope::Global,
        request_id,
        request_id,
    )
}

pub fn connection_request_offer(owner: FactId, request_id: FactId) -> ContextOffer {
    ContextOffer::range(
        owner,
        CONNECTION_REQUEST_ROLE,
        FactScope::Global,
        request_id,
        request_id,
    )
}

pub fn connection_for_request_need(owner: FactId, request_id: FactId) -> ContextNeed {
    ContextNeed::range(
        owner,
        CONNECTION_FOR_REQUEST_ROLE,
        FactScope::Local,
        request_id,
        request_id,
    )
}

pub fn connection_for_request_offer(owner: FactId, request_id: FactId) -> ContextOffer {
    ContextOffer::range(
        owner,
        CONNECTION_FOR_REQUEST_ROLE,
        FactScope::Local,
        request_id,
        request_id,
    )
}

/// Staged read pipeline for the connection-request fact.
pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "connection::request::Codec",
    authenticate: "connection::request::authenticate::ConnectionRequestAuthenticator",
    adapt: "connection::request::adapt::ConnectionRequestAdapter",
    project: "connection::request::project::ConnectionRequestProjector",
};

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
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_staged::<
            super::Codec,
            super::authenticate::ConnectionRequestAuthenticator,
            super::adapt::ConnectionRequestAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<AuthenticatedConnectionRequest> for ConnectionRequestProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        semantic: AuthenticatedConnectionRequest,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Global {
            return Err("connection request fact must be global".to_string());
        }
        if context.is_replay() {
            return Ok(ProjectionOutput::new());
        }
        // 2-3. Context branch + materialization.
        match semantic {
            AuthenticatedConnectionRequest::Sender { request, base_need } => {
                project_sender_request(fact, &request, context, base_need)
            }
            AuthenticatedConnectionRequest::Receiver { request, base_need } => {
                project_receiver_request(fact, &request, context, base_need)
            }
        }
    }
}

fn project_sender_request(
    fact: &Fact,
    request: &ConnectionRequestFact,
    context: &ProjectionContext,
    base_need: ContextNeed,
) -> Result<ProjectionOutput, String> {
    let mut output = ProjectionOutput::new().need(base_need);
    match request.mode {
        REQUEST_MODE_BOOTSTRAP => {
            let invite_need = invite_secret_need(fact.id, request.invite_secret_fact_id);
            let Some(invite_fact) = context.payload_for(&invite_need) else {
                return Ok(output.need(invite_need));
            };
            if invite_fact.scope != FactScope::Local {
                return Err("connection request invite context must be local".to_string());
            }
            let _invite = invite::decode_fact_payload(invite_fact.body())
                .map_err(|_| "connection request invite context is malformed".to_string())?;
            if invite_fact.id != request.invite_secret_fact_id {
                return Err("connection request invite context does not bind request".to_string());
            }
            output = output.need(invite_need);
        }
        REQUEST_MODE_MEMBERSHIP => {
            let shared_need = endpoint_shared_need(fact.id, request.initiator_endpoint_shared_id);
            let Some(shared_fact) = context.payload_for(&shared_need) else {
                return Ok(output.need(shared_need));
            };
            if shared_fact.scope != FactScope::Global {
                return Err("connection request endpoint_shared context must be global".to_string());
            }
            let shared =
                endpoint_shared::decode_fact_payload(shared_fact.body()).map_err(|_| {
                    "connection request endpoint_shared context is malformed".to_string()
                })?;
            if shared.endpoint_id != request.from_endpoint {
                return Err("connection request endpoint_shared does not bind sender".to_string());
            }
            output = output.need(shared_need);
        }
        _ => unreachable!("validated request mode"),
    }

    let Some(addr) = request.dialed_addr else {
        return Err("connection request dialed_addr is required for sending".to_string());
    };
    Ok(output
        .offer(connection_request_offer(fact.id, fact.id))
        .row_mutation(RowMutation::PutRow(connection_request_row(
            fact.id,
            fact.id,
            request.initiator_ephemeral_secret_fact_id,
            Some(addr),
            fact.body(),
        )?)))
}

fn project_receiver_request(
    fact: &Fact,
    request: &ConnectionRequestFact,
    context: &ProjectionContext,
    base_need: ContextNeed,
) -> Result<ProjectionOutput, String> {
    let observation_need = exact_need(
        fact.id,
        "connection_frame_observation",
        FactScope::Local,
        fact.id,
    );
    let mut output = ProjectionOutput::new()
        .need(base_need)
        .need(observation_need.clone());
    let authority_id = match request.mode {
        REQUEST_MODE_BOOTSTRAP => {
            let invite_need = invite_secret_need(fact.id, request.invite_secret_fact_id);
            let Some(invite_fact) = context.payload_for(&invite_need) else {
                return Ok(output.need(invite_need));
            };
            if invite_fact.scope != FactScope::Local {
                return Err("connection request invite context must be local".to_string());
            }
            let _invite = invite::decode_fact_payload(invite_fact.body())
                .map_err(|_| "connection request invite context is malformed".to_string())?;
            if invite_fact.id != request.invite_secret_fact_id {
                return Err("connection request invite context does not bind request".to_string());
            }
            output = output.need(invite_need);
            request.invite_secret_fact_id
        }
        REQUEST_MODE_MEMBERSHIP => {
            let shared_need = endpoint_shared_need(fact.id, request.initiator_endpoint_shared_id);
            let Some(shared_fact) = context.payload_for(&shared_need) else {
                return Ok(output.need(shared_need));
            };
            if shared_fact.scope != FactScope::Global {
                return Err("connection request endpoint_shared context must be global".to_string());
            }
            let shared =
                endpoint_shared::decode_fact_payload(shared_fact.body()).map_err(|_| {
                    "connection request endpoint_shared context is malformed".to_string()
                })?;
            if shared.endpoint_id != request.from_endpoint {
                return Err("connection request endpoint_shared does not bind sender".to_string());
            }
            let member_need =
                content_signer_need(fact.id, shared.workspace_id, request.to_endpoint);
            let Some(member_fact) = context.payload_for(&member_need) else {
                return Ok(output.need(shared_need).need(member_need));
            };
            let member =
                endpoint_shared::decode_fact_payload(member_fact.body()).map_err(|_| {
                    "connection request mutual membership context is malformed".to_string()
                })?;
            if member.endpoint_id != request.to_endpoint
                || member.workspace_id != shared.workspace_id
            {
                return Err(
                    "connection request mutual membership does not bind receiver".to_string(),
                );
            }
            output = output.need(shared_need).need(member_need);
            request.initiator_endpoint_shared_id
        }
        _ => unreachable!("validated request mode"),
    };

    let Some(observation_fact) = context.payload_for(&observation_need) else {
        return Ok(output);
    };
    if observation_fact.scope != FactScope::Local {
        return Err("connection request observation context must be local".to_string());
    }
    let observation = frame_observation::Codec::decode_fact(observation_fact)
        .map_err(|_| "connection request observation context is malformed".to_string())?;
    if observation.frame_fact_id != fact.id {
        return Err("connection request observation targets another fact".to_string());
    }
    let receipt = connection_fact_receipt_for_path(ConnectionFactReceiptInput {
        received_fact_id: fact.id,
        origin_addr: observation.origin_addr.bytes(),
        local_endpoint_id: request.to_endpoint,
        sender_endpoint_id: request.from_endpoint,
        receive_path:
            crate::protocol::connection::fact_receipt::fact::RECEIVE_PATH_CONNECTION_REQUEST,
        connection_id: None,
        request_id: Some(fact.id),
        frame_hash: crypto::hash(fact.body()),
        received_at_local_ms: observation.received_at_local_ms,
    })?;
    let receive_id = receipt.id;
    Ok(output
        .offer(connection_request_offer(fact.id, fact.id))
        .fact(receipt)
        .intent(create_connection_intent(CreateConnection {
            request_id: fact.id,
            initiator_endpoint_shared_id: authority_id,
            receive_id,
        })))
}

#[cfg(test)]
fn all_ephemeral_secret_need(owner: FactId) -> ContextNeed {
    authenticate::all_ephemeral_secret_need(owner)
}

#[cfg(test)]
fn all_local_endpoint_need(owner: FactId) -> ContextNeed {
    authenticate::all_local_endpoint_need(owner)
}

fn invite_secret_need(owner: FactId, invite_secret_id: FactId) -> ContextNeed {
    authenticate::invite_secret_need(owner, invite_secret_id)
}

fn endpoint_shared_need(owner: FactId, endpoint_shared_id: FactId) -> ContextNeed {
    authenticate::endpoint_shared_need(owner, endpoint_shared_id)
}

fn content_signer_need(owner: FactId, workspace_id: FactId, endpoint_id: FactId) -> ContextNeed {
    ContextNeed::range(
        owner,
        "content_signer",
        workspace::scope(workspace_id),
        endpoint_id,
        endpoint_id,
    )
}

fn exact_need(owner: FactId, role: &'static str, scope: FactScope, key: FactId) -> ContextNeed {
    authenticate::exact_need(owner, role, scope, key)
}

#[cfg(test)]
mod tests {
    use crate::core::crypto;
    use crate::core::facts::{Fact, FactScope};
    use crate::core::intents::RowMutation;
    use crate::core::pipeline::{MatchedContext, ProjectionContext, ProjectionMode, Projector};
    use crate::protocol::auth::endpoint::fact::EndpointFact;
    use crate::protocol::auth::invite::{encode as invite_encode, fact::InviteSecretFact};
    use crate::protocol::connection::ephemeral_secret::{
        encode as ephemeral_encode, fact::ConnectionEphemeralSecretFact,
    };
    use crate::protocol::connection::frame_observation;
    use crate::protocol::connection::request::author;
    use crate::protocol::connection::request::fact::REQUEST_MODE_BOOTSTRAP;
    use crate::protocol::connection::request::CONNECTION_REQUEST_ROWS;

    use super::super::encode;
    use super::*;

    fn endpoint(secret: [u8; 32], signing_secret: [u8; 32]) -> EndpointFact {
        EndpointFact {
            endpoint: crypto::x25519_public_key(&secret),
            secret,
            signing_public_key: crypto::ed25519_public_key(&signing_secret),
            signing_secret,
        }
    }

    fn bootstrap_facts(local: EndpointFact, remote_endpoint: [u8; 32]) -> (Fact, Fact, Fact) {
        let invite_secret = InviteSecretFact::scoped([5; 32], [6; 32], [7; 32]);
        let invite_fact = Fact::new(
            FactScope::Local,
            10,
            invite_encode::encode_fact(&invite_secret).expect("invite"),
        );
        let ephemeral_private_key = [8; 32];
        let ephemeral = ConnectionEphemeralSecretFact {
            owner_endpoint: local.endpoint,
            ephemeral_private_key,
            ephemeral_public_key: crypto::x25519_public_key(&ephemeral_private_key),
            created_at_ms: 11,
        };
        let ephemeral_fact = Fact::new(
            FactScope::Local,
            11,
            ephemeral_encode::encode_fact(&ephemeral).expect("ephemeral"),
        );
        let mut request = ConnectionRequestFact {
            mode: REQUEST_MODE_BOOTSTRAP,
            from_endpoint: local.endpoint,
            to_endpoint: remote_endpoint,
            nonce: [9; 32],
            dialed_addr: Some("127.0.0.1:41000".parse().unwrap()),
            initiator_addr: Some("127.0.0.1:41010".parse().unwrap()),
            invite_fact_id: [7; 32],
            bootstrap_hash: invite_secret.bootstrap_hash,
            invite_secret_fact_id: invite_fact.id,
            invite_signature: [0; crypto::ED25519_SIGNATURE_BYTES],
            initiator_endpoint_shared_id: [0; 32],
            endpoint_signature: [0; crypto::ED25519_SIGNATURE_BYTES],
            initiator_ephemeral_secret_fact_id: ephemeral_fact.id,
            initiator_ephemeral_public_key: ephemeral.ephemeral_public_key,
        };
        author::sign_bootstrap_request(&mut request, &invite_secret).expect("sign request");
        let request_fact = Fact::new(
            FactScope::Global,
            12,
            encode::seal_fact(&request, &ephemeral_private_key).expect("seal request"),
        );
        (invite_fact, ephemeral_fact, request_fact)
    }

    #[test]
    fn sender_request_projection_writes_pending_retry_row() {
        let local = endpoint([1; 32], [2; 32]);
        let remote = endpoint([3; 32], [4; 32]);
        let (invite_fact, ephemeral_fact, request_fact) = bootstrap_facts(local, remote.endpoint);

        let context = ProjectionContext::from_matches(vec![
            MatchedContext {
                need: all_ephemeral_secret_need(request_fact.id),
                offer: ContextOffer::range(
                    ephemeral_fact.id,
                    "connection_ephemeral_secret",
                    FactScope::Local,
                    ephemeral_fact.id,
                    ephemeral_fact.id,
                ),
                payload: ephemeral_fact,
            },
            MatchedContext {
                need: ContextNeed::range(
                    request_fact.id,
                    "connection_invite_secret",
                    FactScope::Local,
                    invite_fact.id,
                    invite_fact.id,
                ),
                offer: ContextOffer::range(
                    invite_fact.id,
                    "connection_invite_secret",
                    FactScope::Local,
                    invite_fact.id,
                    invite_fact.id,
                ),
                payload: invite_fact,
            },
        ]);

        let projected = ConnectionRequestProjector::new()
            .project(&request_fact, &context)
            .expect("project request");

        assert!(projected
            .offers
            .iter()
            .any(|offer| offer.role.as_str() == "connection_request"));
        assert!(projected.effects.row_mutations.iter().any(|mutation| {
            matches!(
                mutation,
                RowMutation::PutRow(row) if row.table == CONNECTION_REQUEST_ROWS
            )
        }));

        let replayed = ConnectionRequestProjector::new()
            .project(&request_fact, &context.with_mode(ProjectionMode::Replay))
            .expect("replay request");
        assert!(replayed.offers.is_empty());
        assert!(replayed.needs.is_empty());
        assert!(replayed.effects.facts.is_empty());
        assert!(replayed.effects.row_mutations.is_empty());
        assert!(replayed.effects.intents.is_empty());
    }

    #[test]
    fn receiver_request_projection_emits_receipt_and_create_connection_intent() {
        let initiator = endpoint([1; 32], [2; 32]);
        let responder = endpoint([3; 32], [4; 32]);
        let (invite_fact, _, request_fact) = bootstrap_facts(initiator, responder.endpoint);
        let endpoint_fact = crate::protocol::auth::endpoint::author::endpoint_fact(11, responder)
            .expect("endpoint fact");
        let observation_fact = frame_observation::author::fact_from_observation(
            request_fact.id,
            b"127.0.0.1:41010",
            12,
        )
        .expect("observation");

        let context = ProjectionContext::from_matches(vec![
            MatchedContext {
                need: all_local_endpoint_need(request_fact.id),
                offer: ContextOffer::range(
                    endpoint_fact.id,
                    "auth_local_endpoint",
                    FactScope::Local,
                    responder.endpoint,
                    responder.endpoint,
                ),
                payload: endpoint_fact,
            },
            MatchedContext {
                need: ContextNeed::range(
                    request_fact.id,
                    "connection_invite_secret",
                    FactScope::Local,
                    invite_fact.id,
                    invite_fact.id,
                ),
                offer: ContextOffer::range(
                    invite_fact.id,
                    "connection_invite_secret",
                    FactScope::Local,
                    invite_fact.id,
                    invite_fact.id,
                ),
                payload: invite_fact,
            },
            MatchedContext {
                need: ContextNeed::range(
                    request_fact.id,
                    "connection_frame_observation",
                    FactScope::Local,
                    request_fact.id,
                    request_fact.id,
                ),
                offer: ContextOffer::range(
                    observation_fact.id,
                    "connection_frame_observation",
                    FactScope::Local,
                    request_fact.id,
                    request_fact.id,
                ),
                payload: observation_fact,
            },
        ]);

        let projected = ConnectionRequestProjector::new()
            .project(&request_fact, &context)
            .expect("project request");

        assert_eq!(projected.effects.facts.len(), 1);
        assert_eq!(projected.effects.intents.len(), 1);
    }
}
