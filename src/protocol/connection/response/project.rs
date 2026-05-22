//! Poc-10 connection-response projector.
//!
//! POLICY. A connection_response is admitted iff:
//!   1. STRUCTURAL. The fact is local-only, response fields are non-empty, and
//!      the response references a different request fact.
//!   2. CONTEXT. Projection validates exact request and invite-secret context.
//!      Received responses additionally require transit provenance plus local
//!      initiator secret; local responses require responder secret.
//!   3. MATERIALIZE. Valid responses write the connection_response row. Network
//!      effects stay in intent handlers.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use crate::protocol::connection::ephemeral_secret;
use crate::protocol::connection::request;
use crate::protocol::identity::invite;
use crate::protocol::transport::transit_received::{
    self, fact::TRANSIT_KIND_CONNECTION_HANDSHAKE,
};
use crate::protocol::sync::seed_connection::{
    seed_connection_sync_intent, SeedConnectionSync,
};

use super::create;
use super::fact::ConnectionResponseFact;
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
            return Err("connection response fact must have local scope".to_string());
        }
        validate_response_fields(&response)?;
        if response.from_endpoint == response.to_endpoint {
            return Err("connection response endpoints must differ".to_string());
        }
        if response.request_id == fact.id {
            return Err("connection response cannot answer itself".to_string());
        }

        // 2. Shared request and invite context.
        let request_need = crate::core::context::ContextNeed::range(
            fact.id,
            "connection_request",
            crate::core::facts::FactScope::Global,
            response.request_id,
            response.request_id,
        );
        let Some(request_context) = projection_context.payload_for(&request_need) else {
            return Ok(waiting_output([request_need]));
        };
        let request = request::decode_fact_payload(request_context.body())
            .map_err(|_| "connection response context is not a request fact".to_string())?;
        if request_context.id != response.request_id {
            return Err(
                "connection response request context id does not match response".to_string(),
            );
        }
        if !matches!(request_context.scope, FactScope::Local | FactScope::Global) {
            return Err("connection response request context has unsupported scope".to_string());
        }
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

        let responder_ephemeral_need = crate::core::context::ContextNeed::range(
            fact.id,
            "connection_ephemeral_secret",
            crate::core::facts::FactScope::Local,
            response.responder_ephemeral_secret_fact_id,
            response.responder_ephemeral_secret_fact_id,
        );
        let receive_need = crate::core::context::ContextNeed::range(
            fact.id,
            "transport_transit_received",
            crate::core::facts::FactScope::Local,
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
                return Err("connection response receive context must be local".to_string());
            }
            let received = transit_received::decode_fact_payload(receive.body()).map_err(|_| {
                "connection response receive context is not transport::transit provenance"
                    .to_string()
            })?;
            validate_receive_provenance(fact.id, &response, &received)?;
            let initiator_ephemeral_need = crate::core::context::ContextNeed::range(
                fact.id,
                "connection_ephemeral_secret",
                crate::core::facts::FactScope::Local,
                response.initiator_ephemeral_secret_fact_id,
                response.initiator_ephemeral_secret_fact_id,
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
            let initiator_secret = ephemeral_secret::decode_fact_payload(
                initiator_ephemeral.body(),
            )
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
            return materialized_output(fact.id, &response);
        }

        // 2b. Local response path.
        let Some(responder_ephemeral) = projection_context.payload_for(&responder_ephemeral_need)
        else {
            return Ok(waiting_output([
                request_need,
                invite_need,
                responder_ephemeral_need,
                receive_need,
            ]));
        };
        let responder_secret = ephemeral_secret::decode_fact_payload(responder_ephemeral.body())
            .map_err(|_| {
                "connection response responder dependency is not an ephemeral secret".to_string()
            })?;
        if responder_ephemeral.id != response.responder_ephemeral_secret_fact_id {
            return Err(
                "connection response responder ephemeral context id does not match response"
                    .to_string(),
            );
        }
        if responder_ephemeral.scope != FactScope::Local {
            return Err(
                "connection response responder ephemeral context must be local".to_string(),
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
        // 3. Materialize local response.
        materialized_output(fact.id, &response)
    }
}

fn validate_response_fields(response: &ConnectionResponseFact) -> Result<(), String> {
    if response.from_endpoint == [0; 32] {
        return Err("connection response from_endpoint cannot be empty".to_string());
    }
    if response.to_endpoint == [0; 32] {
        return Err("connection response to_endpoint cannot be empty".to_string());
    }
    if response.request_id == [0; 32] {
        return Err("connection response request_id cannot be empty".to_string());
    }
    if response.invite_secret_fact_id == [0; 32] {
        return Err("connection response invite_secret_fact_id cannot be empty".to_string());
    }
    if response.initiator_ephemeral_secret_fact_id == [0; 32] {
        return Err(
            "connection response initiator_ephemeral_secret_fact_id cannot be empty".to_string(),
        );
    }
    if response.responder_ephemeral_secret_fact_id == [0; 32] {
        return Err(
            "connection response responder_ephemeral_secret_fact_id cannot be empty".to_string(),
        );
    }
    if response.responder_ephemeral_public_key == [0; 32] {
        return Err(
            "connection response responder_ephemeral_public_key cannot be empty".to_string(),
        );
    }
    if response.handshake_hash == [0; 32] {
        return Err("connection response handshake_hash cannot be empty".to_string());
    }
    if response.connection_secret == [0; 32] {
        return Err("connection response connection_secret cannot be empty".to_string());
    }
    Ok(())
}

fn validate_request_response(
    response: &ConnectionResponseFact,
    request: &crate::protocol::connection::request::fact::ConnectionRequestFact,
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

fn validate_receive_provenance(
    response_id: [u8; 32],
    response: &ConnectionResponseFact,
    received: &crate::protocol::transport::transit_received::fact::TransitReceivedFact,
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
    Ok(ProjectionOutput::new()
        .row_mutation(RowMutation::PutRow(connection_response_row(
            response_id,
            response,
        )?))
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

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::crypto::{self, ED25519_SIGNATURE_BYTES};
    use topo::core::facts::{Fact, FactScope};
    use topo::core::intents::RowMutation;
    use topo::core::projectors::{MatchedContext, ProjectionContext, Projector};
    use topo::protocol::connection::ephemeral_secret::{
        fact::ConnectionEphemeralSecretFact, layout as ephemeral_layout,
    };
    use topo::protocol::connection::request::{
        addr::encode_optional_addr, fact::ConnectionRequestFact, layout as request_layout,
    };
    use topo::protocol::connection::response::{create, layout, project, rows};
    use topo::protocol::identity::endpoint::fact::EndpointFact;
    use topo::protocol::identity::invite::{
        fact::InviteSecretFact, layout as invite_layout,
    };
    use topo::protocol::transport::transit_received::{
        fact::{TransitReceivedFact, TRANSIT_KIND_CONNECTION_HANDSHAKE},
        layout as received_layout,
    };

    struct Scenario {
        request_fact: Fact,
        invite_fact: Fact,
        initiator_ephemeral_fact: Fact,
        responder_ephemeral_fact: Fact,
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
        let mut request = ConnectionRequestFact {
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
            responder_ephemeral_fact,
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

    fn request_match(owner: [u8; 32], request: Fact) -> MatchedContext {
        MatchedContext {
            need: crate::core::context::ContextNeed::range(
                owner,
                "connection_request",
                crate::core::facts::FactScope::Global,
                request.id,
                request.id,
            ),
            offer: crate::core::context::ContextOffer::range(
                request.id,
                "connection_request",
                crate::core::facts::FactScope::Global,
                request.id,
                request.id,
            ),
            payload: request,
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
        response: &topo::protocol::connection::response::fact::ConnectionResponseFact,
    ) -> MatchedContext {
        let received = TransitReceivedFact {
            received_fact_id: response_id,
            origin_addr: b"127.0.0.1:41002".to_vec(),
            local_endpoint_id: response.to_endpoint,
            sender_endpoint_id: response.from_endpoint,
            transit_kind: TRANSIT_KIND_CONNECTION_HANDSHAKE,
            connection_id: Some(response_id),
            request_id: Some(request_id),
            frame_hash: [8; 32],
            received_at_local_ms: 1_700_000_001,
        };
        let fact = Fact::new(
            FactScope::Local,
            15,
            received_layout::encode_fact(&received).expect("encode provenance"),
        );
        MatchedContext {
            need: crate::core::context::ContextNeed::range(
                owner,
                "transport_transit_received",
                crate::core::facts::FactScope::Local,
                response_id,
                response_id,
            ),
            offer: crate::core::context::ContextOffer::range(
                fact.id,
                "transport_transit_received",
                crate::core::facts::FactScope::Local,
                response_id,
                response_id,
            ),
            payload: fact,
        }
    }

    #[test]
    fn response_missing_request_waits_without_row() {
        let scenario = scenario();
        let context = ProjectionContext::from_matches(vec![
            invite_match(scenario.response_fact.id, scenario.invite_fact),
            ephemeral_match(scenario.response_fact.id, scenario.responder_ephemeral_fact),
        ]);

        let output = project::ConnectionResponseProjector::new()
            .project(&scenario.response_fact, &context)
            .expect("project waits");

        assert!(output.effects.intents.is_empty());
        assert!(output
            .needs
            .iter()
            .any(|need| need.role == "connection_request"));
    }

    #[test]
    fn local_response_materializes_after_request_invite_and_responder_ephemeral_context() {
        let scenario = scenario();
        let context = ProjectionContext::from_matches(vec![
            request_match(scenario.response_fact.id, scenario.request_fact.clone()),
            invite_match(scenario.response_fact.id, scenario.invite_fact.clone()),
            ephemeral_match(
                scenario.response_fact.id,
                scenario.responder_ephemeral_fact.clone(),
            ),
        ]);

        let output = project::ConnectionResponseProjector::new()
            .project(&scenario.response_fact, &context)
            .expect("project response");

        assert_eq!(output.effects.intents.len(), 1);
        assert_eq!(output.effects.row_mutations.len(), 1);
        let RowMutation::PutRow(row) = &output.effects.row_mutations[0] else {
            panic!("expected put row mutation");
        };
        let response = layout::decode_fact(&scenario.response_fact.bytes).expect("decode response");
        let row = rows::decode_connection_response_row(&row.key, &row.value)
            .expect("decode connection response row");
        assert_eq!(row.connection_id, scenario.response_fact.id);
        assert_eq!(row.from_endpoint, response.from_endpoint);
        assert_eq!(row.to_endpoint, response.to_endpoint);
        assert_eq!(row.request_id, response.request_id);
        assert_eq!(
            row.responder_ephemeral_public_key,
            response.responder_ephemeral_public_key
        );
        assert_eq!(row.handshake_hash, response.handshake_hash);
        assert_eq!(row.connection_secret, response.connection_secret);
    }

    #[test]
    fn received_response_materializes_after_provenance_and_initiator_ephemeral_context() {
        let scenario = scenario();
        let response = layout::decode_fact(&scenario.response_fact.bytes).expect("decode response");
        let context = ProjectionContext::from_matches(vec![
            request_match(scenario.response_fact.id, scenario.request_fact.clone()),
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

        let output = project::ConnectionResponseProjector::new()
            .project(&scenario.response_fact, &context)
            .expect("project received response");

        assert_eq!(output.effects.intents.len(), 1);
        assert_eq!(output.effects.row_mutations.len(), 1);
        let RowMutation::PutRow(row) = &output.effects.row_mutations[0] else {
            panic!("expected put row mutation");
        };
        let row = rows::decode_connection_response_row(&row.key, &row.value)
            .expect("decode connection response row");
        assert_eq!(row.connection_id, scenario.response_fact.id);
        assert_eq!(row.to_endpoint, response.to_endpoint);
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
        let err = project::ConnectionResponseProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect_err("self-loop endpoints must fail projection");
        assert!(err.contains("endpoints"), "{err}");
    }

    #[test]
    fn connection_response_projector_rejects_malformed_bytes() {
        let fact = Fact::new(FactScope::Local, 0, vec![0; 4]);
        let err = project::ConnectionResponseProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect_err("malformed bytes must fail projection");
        assert!(
            err.contains("connection response") || err.contains("Length"),
            "{err}"
        );
    }

    fn invite_signing_transcript(request: &ConnectionRequestFact) -> Result<Vec<u8>, String> {
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
