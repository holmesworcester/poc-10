//! Connection-response projector.
//!
//! Response projection turns a received bootstrap handshake answer into local
//! connection state. The responder-side authoring path records
//! `bootstrap_response_sent` and `connection_established`; this projector handles
//! the initiator receive path after sealed response bytes are opened into this
//! canonical `bootstrap_response` fact.
//!
//! POLICY. A connection_response is admitted iff:
//!   1. STRUCTURAL. The fact is local-only, response fields are non-empty, and
//!      the response references a different request fact.
//!   2. CONTEXT. Projection validates exact request-sent context, invite-secret
//!      context, connection fact receipt, and the local initiator secret.
//!   3. MATERIALIZE. Valid responses emit `bootstrap_response_received`,
//!      `connection_established`; the established projector seeds sync once the
//!      live connection row exists.
//!
//! Change this projector for response admission, context waits, connection
//! context offers, or established-state emission. Response byte compatibility
//! belongs in `layout.rs`; key-schedule construction belongs in `create.rs`.

use crate::core::facts::{Fact, FactScope};
use crate::core::projectors::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
};

use crate::protocol::auth::invite;
use crate::protocol::connection::bootstrap_request_sent as request_sent_family;
use crate::protocol::connection::bootstrap_response_received;
use crate::protocol::connection::bootstrap_response_received::fact::BootstrapResponseReceivedFact;
use crate::protocol::connection::close;
use crate::protocol::connection::connection_established;
use crate::protocol::connection::connection_established::fact::ConnectionEstablishedFact;
use crate::protocol::connection::ephemeral_secret;
use crate::protocol::connection::fact_receipt::{self, fact::RECEIVE_PATH_CONNECTION_RESPONSE};

use super::create;
use super::fact::BootstrapResponseFact;

#[derive(Debug, Clone, Default)]
pub struct BootstrapResponseProjector;

impl BootstrapResponseProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for BootstrapResponseProjector {
    fn project(
        &self,
        fact: &Fact,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_authenticated::<super::authenticate::BootstrapResponseAuthenticator, _>(
            self,
            fact,
            projection_context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::BootstrapResponseAuthenticator>
    for BootstrapResponseProjector
{
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, BootstrapResponseFact>,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // Authentication (see authenticate.rs) proved canonical bytes and the
        // intrinsic response fields. Scope is interpretation.
        let (fact, response) = authenticated.into_parts();
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("connection response fact must have local scope".to_string());
        }
        let close_need = close::connection_closed_need(fact.id, fact.id);
        if let Some(close_fact) = projection_context.payload_for(&close_need) {
            if close_fact.scope != FactScope::Local {
                return Err("connection response close context must be local".to_string());
            }
            return Ok(ProjectionOutput::new().purge_self(fact.id));
        }

        // 2. Local request-sent context.
        let request_need =
            request_sent_family::project::bootstrap_request_sent_need(fact.id, response.request_id);
        let Some(request_context) = projection_context.payload_for(&request_need) else {
            return Ok(waiting_output([request_need]));
        };
        if request_context.scope != FactScope::Local {
            return Err("connection response request-sent context must be local".to_string());
        }
        let sent = request_sent_family::decode_fact_payload(request_context.body())
            .map_err(|_| "connection response context is not bootstrap_request_sent".to_string())?;
        let request = sent.request;
        validate_request_response(&response, &request)?;

        let invite_need = crate::core::context::ContextNeed::range(
            fact.id,
            "connection_invite_secret",
            crate::core::facts::FactScope::Local,
            response.invite_secret_fact_id,
            response.invite_secret_fact_id,
        );
        let Some(invite_context) = projection_context.payload_for(&invite_need) else {
            return Ok(waiting_output([request_need, invite_need]));
        };
        let invite = invite::decode_fact_payload(invite_context.body()).map_err(|_| {
            "connection response invite context is not an invite secret".to_string()
        })?;
        if invite_context.id != response.invite_secret_fact_id {
            return Err(
                "connection response invite context id does not match response".to_string(),
            );
        }
        if invite_context.scope != FactScope::Local {
            return Err("connection response invite context must be local".to_string());
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

        let receive_need = crate::core::context::ContextNeed::range(
            fact.id,
            "connection_fact_receipt",
            crate::core::facts::FactScope::Local,
            fact.id,
            fact.id,
        );

        let Some(receive) = projection_context
            .matched_payloads_for(&receive_need)
            .map(|(_, fact)| fact)
            .min_by_key(|fact| fact.id)
        else {
            return Ok(waiting_output([request_need, invite_need, receive_need]));
        };
        if receive.scope != FactScope::Local {
            return Err("connection response receive context must be local".to_string());
        }
        let received = fact_receipt::decode_fact_payload(receive.body()).map_err(|_| {
            "connection response receive context is not connection fact receipt".to_string()
        })?;
        validate_fact_receipt(fact.id, &response, &received)?;
        let initiator_ephemeral_need = crate::core::context::ContextNeed::range(
            fact.id,
            "connection_ephemeral_secret",
            crate::core::facts::FactScope::Local,
            response.initiator_ephemeral_secret_fact_id,
            response.initiator_ephemeral_secret_fact_id,
        );
        let Some(initiator_ephemeral) = projection_context.payload_for(&initiator_ephemeral_need)
        else {
            return Ok(waiting_output([
                request_need,
                invite_need,
                receive_need,
                initiator_ephemeral_need,
            ]));
        };
        let initiator_secret = ephemeral_secret::decode_fact_payload(initiator_ephemeral.body())
            .map_err(|_| {
                "connection response initiator dependency is not an ephemeral secret".to_string()
            })?;
        if initiator_ephemeral.id != response.initiator_ephemeral_secret_fact_id {
            return Err(
                "connection response initiator ephemeral context id does not match response"
                    .to_string(),
            );
        }
        if initiator_ephemeral.scope != FactScope::Local {
            return Err(
                "connection response initiator ephemeral context must be local".to_string(),
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
        // 3. Materialize received response.
        materialized_output(
            fact,
            &response,
            receive.id,
            received.received_at_local_ms,
            close_need,
        )
    }
}

fn validate_request_response(
    response: &BootstrapResponseFact,
    request: &crate::protocol::connection::bootstrap_request::fact::BootstrapRequestFact,
) -> Result<(), String> {
    if request.from_endpoint != response.to_endpoint {
        return Err("connection response references another endpoint's request".to_string());
    }
    if request.to_endpoint != response.from_endpoint {
        return Err("connection response sender does not match request recipient".to_string());
    }
    if response.invite_secret_fact_id != request.invite_secret_fact_id {
        return Err("connection response invite dependency does not match request".to_string());
    }
    if response.initiator_ephemeral_secret_fact_id != request.initiator_ephemeral_secret_fact_id {
        return Err("connection response initiator ephemeral does not match request".to_string());
    }
    Ok(())
}

fn validate_fact_receipt(
    response_id: [u8; 32],
    response: &BootstrapResponseFact,
    received: &crate::protocol::connection::fact_receipt::fact::ConnectionFactReceipt,
) -> Result<(), String> {
    if received.received_fact_id != response_id {
        return Err("connection response receive context targets another fact".to_string());
    }
    if received.receive_path != RECEIVE_PATH_CONNECTION_RESPONSE {
        return Err("connection response requires connection response receipt".to_string());
    }
    if received.local_endpoint_id != response.to_endpoint {
        return Err("connection response addressed to a different endpoint".to_string());
    }
    if received.sender_endpoint_id != response.from_endpoint {
        return Err("connection response sender does not match receive sender".to_string());
    }
    if received.request_id != Some(response.request_id) {
        return Err("connection response fact receipt names another request".to_string());
    }
    if let Some(connection_id) = received.connection_id {
        if connection_id != response_id {
            return Err("connection response fact receipt names another connection".to_string());
        }
    }
    Ok(())
}

fn materialized_output(
    fact: &Fact,
    response: &BootstrapResponseFact,
    receive_id: [u8; 32],
    received_at_local_ms: u64,
    close_need: crate::core::context::ContextNeed,
) -> Result<ProjectionOutput, String> {
    let response_id = fact.id;
    let response_received = Fact::new(
        FactScope::Local,
        received_at_local_ms,
        bootstrap_response_received::layout::encode_fact(&BootstrapResponseReceivedFact {
            response_id,
            request_id: response.request_id,
            receive_id,
            received_at_local_ms,
        })?,
    );
    let established = Fact::new(
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
        .need(close_need)
        .fact(response_received)
        .fact(established))
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

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::crypto::{self, ED25519_SIGNATURE_BYTES};
    use topo::core::facts::{Fact, FactScope};
    use topo::core::projectors::{MatchedContext, ProjectionContext, Projector};
    use topo::protocol::auth::endpoint::fact::EndpointFact;
    use topo::protocol::auth::invite::{fact::InviteSecretFact, layout as invite_layout};
    use topo::protocol::connection::bootstrap_request::create::encode_optional_addr;
    use topo::protocol::connection::bootstrap_request::{
        fact::BootstrapRequestFact, layout as request_layout, transit as request_transit,
    };
    use topo::protocol::connection::bootstrap_request_sent::{
        fact::BootstrapRequestSentFact, layout as request_sent_layout,
        project as request_sent_project,
    };
    use topo::protocol::connection::bootstrap_response::{create, layout, project};
    use topo::protocol::connection::bootstrap_response_received::layout as response_received_layout;
    use topo::protocol::connection::connection_established::layout as established_layout;
    use topo::protocol::connection::ephemeral_secret::{
        fact::ConnectionEphemeralSecretFact, layout as ephemeral_layout,
    };
    use topo::protocol::connection::fact_receipt::{
        fact::{ConnectionFactReceipt, RECEIVE_PATH_CONNECTION_RESPONSE},
        layout as received_layout,
    };

    struct Scenario {
        request_fact: Fact,
        invite_fact: Fact,
        initiator_ephemeral_fact: Fact,
        response_fact: Fact,
    }

    fn scenario() -> Scenario {
        let invite = InviteSecretFact::new([55; 32]);
        let invite_fact = Fact::new(
            FactScope::Local,
            10,
            invite_layout::encode_fact(&invite).expect("encode invite"),
        );
        let initiator_endpoint = crypto::x25519_public_key(&[11; 32]);
        let responder_static = [22; 32];
        let responder_endpoint = crypto::x25519_public_key(&responder_static);
        let (initiator_ephemeral, initiator_ephemeral_fact) =
            ephemeral_fact(initiator_endpoint, [33; 32], 11);
        let (responder_ephemeral, responder_ephemeral_fact) =
            ephemeral_fact(responder_endpoint, [44; 32], 12);
        let mut request = BootstrapRequestFact {
            from_endpoint: initiator_endpoint,
            to_endpoint: responder_endpoint,
            nonce: [77; 32],
            invite_fact_id: [88; 32],
            bootstrap_hash: invite.bootstrap_hash,
            invite_signature: [0; ED25519_SIGNATURE_BYTES],
            invite_secret_fact_id: invite_fact.id,
            initiator_ephemeral_secret_fact_id: initiator_ephemeral_fact.id,
            initiator_ephemeral_public_key: initiator_ephemeral.ephemeral_public_key,
            from_listen_addr: None,
            to_listen_addr: None,
        };
        request.invite_signature = crypto::ed25519_sign(
            &invite.bootstrap_secret,
            &invite_signing_transcript(&request).expect("transcript"),
        );
        let request_fact = Fact::new(
            FactScope::Global,
            13,
            request_layout::encode_fact(&request).expect("encode request"),
        );
        let endpoint = EndpointFact {
            endpoint: responder_endpoint,
            secret: responder_static,
            signing_public_key: crypto::ed25519_public_key(&[99; 32]),
            signing_secret: [99; 32],
        };
        let built = create::build_responder_response(create::BuildResponderResponse {
            request_id: request_fact.id,
            request: &request,
            invite: &invite,
            endpoint: &endpoint,
            responder_ephemeral_private_key: responder_ephemeral.ephemeral_private_key,
            responder_ephemeral_secret_fact_id: responder_ephemeral_fact.id,
            created_at_ms: 14,
        })
        .expect("build response");
        Scenario {
            request_fact,
            invite_fact,
            initiator_ephemeral_fact,
            response_fact: built.fact,
        }
    }

    fn ephemeral_fact(
        owner_endpoint: [u8; 32],
        private_key: [u8; 32],
        timestamp: u64,
    ) -> (ConnectionEphemeralSecretFact, Fact) {
        let secret = ConnectionEphemeralSecretFact {
            owner_endpoint,
            ephemeral_private_key: private_key,
            ephemeral_public_key: crypto::x25519_public_key(&private_key),
            created_at_ms: timestamp,
        };
        let fact = Fact::new(
            FactScope::Local,
            timestamp,
            ephemeral_layout::encode_fact(&secret).expect("encode ephemeral"),
        );
        (secret, fact)
    }

    fn sealed_request_bytes() -> [u8; request_transit::SEALED_CONNECTION_REQUEST_BYTES] {
        let mut bytes = [0u8; request_transit::SEALED_CONNECTION_REQUEST_BYTES];
        bytes[0] = request_transit::TYPE_SEALED_CONNECTION_REQUEST;
        bytes[1] = 1;
        bytes
    }

    fn request_sent_match(owner: [u8; 32], request_fact: Fact) -> MatchedContext {
        let request_id = request_fact.id;
        let request = request_layout::decode_fact(request_fact.body()).expect("decode request");
        let sent = BootstrapRequestSentFact {
            request_id,
            initiator_ephemeral_secret_fact_id: request.initiator_ephemeral_secret_fact_id,
            peer_addr: "127.0.0.1:41002".parse().expect("peer addr"),
            request,
            sealed_request_bytes: sealed_request_bytes(),
            created_at_ms: 13,
        };
        let fact = Fact::new(
            FactScope::Local,
            13,
            request_sent_layout::encode_fact(&sent).expect("encode request sent"),
        );
        MatchedContext {
            need: request_sent_project::bootstrap_request_sent_need(owner, request_id),
            offer: request_sent_project::bootstrap_request_sent_offer(fact.id, request_id),
            payload: fact,
        }
    }

    fn invite_match(owner: [u8; 32], invite: Fact) -> MatchedContext {
        MatchedContext {
            need: crate::core::context::ContextNeed::range(
                owner,
                "connection_invite_secret",
                crate::core::facts::FactScope::Local,
                invite.id,
                invite.id,
            ),
            offer: crate::core::context::ContextOffer::range(
                invite.id,
                "connection_invite_secret",
                crate::core::facts::FactScope::Local,
                invite.id,
                invite.id,
            ),
            payload: invite,
        }
    }

    fn ephemeral_match(owner: [u8; 32], ephemeral: Fact) -> MatchedContext {
        MatchedContext {
            need: crate::core::context::ContextNeed::range(
                owner,
                "connection_ephemeral_secret",
                crate::core::facts::FactScope::Local,
                ephemeral.id,
                ephemeral.id,
            ),
            offer: crate::core::context::ContextOffer::range(
                ephemeral.id,
                "connection_ephemeral_secret",
                crate::core::facts::FactScope::Local,
                ephemeral.id,
                ephemeral.id,
            ),
            payload: ephemeral,
        }
    }

    fn receive_match(
        owner: [u8; 32],
        response_id: [u8; 32],
        request_id: [u8; 32],
        response: &topo::protocol::connection::bootstrap_response::fact::BootstrapResponseFact,
    ) -> MatchedContext {
        let received = ConnectionFactReceipt {
            received_fact_id: response_id,
            origin_addr: crate::protocol::connection::fact_receipt::fact::OriginAddr::new(
                b"127.0.0.1:41002",
            )
            .expect("origin"),
            local_endpoint_id: response.to_endpoint,
            sender_endpoint_id: response.from_endpoint,
            receive_path: RECEIVE_PATH_CONNECTION_RESPONSE,
            connection_id: Some(response_id),
            request_id: Some(request_id),
            frame_hash: [8; 32],
            received_at_local_ms: 1_700_000_001,
        };
        let fact = Fact::new(
            FactScope::Local,
            15,
            received_layout::encode_fact(&received).expect("encode receipt"),
        );
        MatchedContext {
            need: crate::core::context::ContextNeed::range(
                owner,
                "connection_fact_receipt",
                crate::core::facts::FactScope::Local,
                response_id,
                response_id,
            ),
            offer: crate::core::context::ContextOffer::range(
                fact.id,
                "connection_fact_receipt",
                crate::core::facts::FactScope::Local,
                response_id,
                response_id,
            ),
            payload: fact,
        }
    }

    #[test]
    fn response_missing_request_sent_waits_without_facts() {
        let scenario = scenario();

        let output = project::BootstrapResponseProjector::new()
            .project(&scenario.response_fact, &ProjectionContext::new(Vec::new()))
            .expect("project waits");

        assert!(output.effects.intents.is_empty());
        assert!(output.effects.facts.is_empty());
        assert!(output
            .needs
            .iter()
            .any(|need| need.role == "bootstrap_request_sent"));
    }

    #[test]
    fn received_response_materializes_lifecycle_facts_after_request_sent_and_receipt_context() {
        let scenario = scenario();
        let response = layout::decode_fact(&scenario.response_fact.bytes).expect("decode response");
        let context = ProjectionContext::from_matches(vec![
            request_sent_match(scenario.response_fact.id, scenario.request_fact.clone()),
            invite_match(scenario.response_fact.id, scenario.invite_fact.clone()),
            ephemeral_match(
                scenario.response_fact.id,
                scenario.initiator_ephemeral_fact.clone(),
            ),
            receive_match(
                scenario.response_fact.id,
                scenario.response_fact.id,
                scenario.request_fact.id,
                &response,
            ),
        ]);

        let output = project::BootstrapResponseProjector::new()
            .project(&scenario.response_fact, &context)
            .expect("project response");

        assert!(output.effects.intents.is_empty());
        assert!(output.time_wakes.is_empty());
        assert!(output.effects.row_mutations.is_empty());
        assert_eq!(output.effects.facts.len(), 2);
        let received = response_received_layout::decode_fact(output.effects.facts[0].body())
            .expect("decode response received");
        let established = established_layout::decode_fact(output.effects.facts[1].body())
            .expect("decode connection established");
        assert_eq!(received.response_id, scenario.response_fact.id);
        assert_eq!(received.request_id, scenario.request_fact.id);
        assert_eq!(established.connection_id, scenario.response_fact.id);
        assert_eq!(established.from_endpoint, response.from_endpoint);
        assert_eq!(established.to_endpoint, response.to_endpoint);
        assert_eq!(established.request_id, response.request_id);
        assert_eq!(established.connection_secret, response.connection_secret);
    }

    #[test]
    fn connection_response_projector_rejects_self_loop_endpoints() {
        let mut response = layout::decode_fact(&scenario().response_fact.bytes).expect("response");
        response.to_endpoint = response.from_endpoint;
        let fact = Fact::new(
            FactScope::Local,
            0,
            layout::encode_fact(&response).expect("encode response"),
        );
        let err = project::BootstrapResponseProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect_err("self-loop endpoints must fail projection");
        assert!(err.contains("endpoints"), "{err}");
    }

    #[test]
    fn connection_response_projector_rejects_malformed_bytes() {
        let fact = Fact::new(FactScope::Local, 0, vec![0; 4]);
        let err = project::BootstrapResponseProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect_err("malformed bytes must fail projection");
        assert!(
            err.contains("connection response") || err.contains("Length"),
            "{err}"
        );
    }

    fn invite_signing_transcript(request: &BootstrapRequestFact) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        out.extend_from_slice(b"topo-connection-request-invite-signing-transcript-v1");
        out.extend_from_slice(&request.from_endpoint);
        out.extend_from_slice(&request.to_endpoint);
        out.extend_from_slice(&request.nonce);
        out.extend_from_slice(&request.invite_fact_id);
        out.extend_from_slice(&request.bootstrap_hash);
        out.extend_from_slice(&request.invite_secret_fact_id);
        out.extend_from_slice(&request.initiator_ephemeral_secret_fact_id);
        out.extend_from_slice(&request.initiator_ephemeral_public_key);
        out.extend_from_slice(&encode_optional_addr(request.from_listen_addr)?);
        out.extend_from_slice(&encode_optional_addr(request.to_listen_addr)?);
        Ok(out)
    }
}
