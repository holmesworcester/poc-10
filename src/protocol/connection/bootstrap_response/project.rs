//! Connection-response projector.
//!
//! Response projection turns a validated handshake answer into local connection
//! context. Both local and received responses prove exact request and
//! invite-secret context; received responses additionally prove a fact receipt
//! and the initiator ephemeral secret, while local responses prove responder
//! ephemeral material.
//!
//! POLICY. A connection_response is admitted iff:
//!   1. STRUCTURAL. The fact is local-only, response fields are non-empty, and
//!      the response references a different request fact.
//!   2. CONTEXT. Projection validates exact request and invite-secret context.
//!      Received responses additionally require connection fact receipt plus local
//!      initiator secret; local responses require responder secret. Close
//!      context removes the response row and purges this response fact.
//!   3. MATERIALIZE. Valid responses write the connection_response row, publish
//!      local connection context. Only received responses emit the initial
//!      one-shot sync seed, because the peer that receives the response owns the
//!      single bidirectional bootstrap sync.
//!
//! Change this projector for response admission, context waits, connection
//! context offers, or sync seeding. Response byte compatibility belongs in
//! `layout.rs`; key-schedule construction belongs in `create.rs`.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::{RowMutation, TableDelete};
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use crate::protocol::auth::invite;
use crate::protocol::connection::fact_receipt::{self, fact::RECEIVE_PATH_CONNECTION_RESPONSE};
use crate::protocol::connection::bootstrap_request as request;
use crate::protocol::connection::send_bootstrap_response::{
    send_bootstrap_connection_response_intent, SendBootstrapConnectionResponse,
};
use crate::protocol::connection::{close, ephemeral_secret};
use crate::protocol::sync::seed_connection::{seed_connection_sync_intent, SeedConnectionSync};

use super::create;
use super::fact::BootstrapResponseFact;
use super::rows::{bootstrap_response_key, bootstrap_response_row, BOOTSTRAP_RESPONSE_ROWS};

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
        project_typed::<super::Codec, _>(self, fact, projection_context)
    }
}

impl TypedProjector<super::Codec> for BootstrapResponseProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        response: BootstrapResponseFact,
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

        // 2. Close gate.
        let close_need = close::connection_closed_need(fact.id, fact.id);
        if let Some(close_fact) = projection_context.payload_for(&close_need) {
            if close_fact.scope != FactScope::Local {
                return Err("connection response close context must be local".to_string());
            }
            let close = close::decode_fact_payload(close_fact.body()).map_err(|_| {
                "connection response close context is not a connection close".to_string()
            })?;
            if close.connection_id != fact.id {
                return Err("connection response close context targets another connection".into());
            }
            return closed_output(fact.id);
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
            "connection_fact_receipt",
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
            return materialized_output(fact, &response, SeedSync::Immediate);
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
        // 3. Materialize the local response and queue its send. Flat-intent rule:
        // create_bootstrap_response only creates the responder ephemeral and
        // response facts; this projector emits the send once the local response
        // fact is admitted, mirroring how the local request projector emits its
        // own send. The bytes are backed by the now-durable response fact.
        let mut output = materialized_output(fact, &response, SeedSync::None)?;
        if let Some(addr) = request.from_listen_addr {
            output = output.intent(send_bootstrap_connection_response_intent(
                SendBootstrapConnectionResponse {
                    response_id: fact.id,
                    responder_ephemeral_secret_id: response.responder_ephemeral_secret_fact_id,
                    addr,
                },
            )?);
        }
        Ok(output)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeedSync {
    None,
    Immediate,
}

fn validate_response_fields(response: &BootstrapResponseFact) -> Result<(), String> {
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
    seed_sync: SeedSync,
) -> Result<ProjectionOutput, String> {
    let response_id = fact.id;
    let mut output = ProjectionOutput::new()
        .need(close::connection_closed_need(response_id, response_id))
        .offer(crate::core::context::ContextOffer::range(
            response_id,
            "connection_response",
            crate::core::facts::FactScope::Local,
            response_id,
            response_id,
        ))
        .offer(request::connection_response_for_request_offer(
            response_id,
            response.request_id,
        ))
        .row_mutation(RowMutation::PutRow(bootstrap_response_row(
            response_id,
            response,
        )?));
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

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::crypto::{self, ED25519_SIGNATURE_BYTES};
    use topo::core::facts::{Fact, FactScope};
    use topo::core::intents::RowMutation;
    use topo::core::projectors::{MatchedContext, ProjectionContext, Projector};
    use topo::protocol::auth::endpoint::fact::EndpointFact;
    use topo::protocol::auth::invite::{fact::InviteSecretFact, layout as invite_layout};
    use topo::protocol::connection::ephemeral_secret::{
        fact::ConnectionEphemeralSecretFact, layout as ephemeral_layout,
    };
    use topo::protocol::connection::fact_receipt::{
        fact::{ConnectionFactReceipt, RECEIVE_PATH_CONNECTION_RESPONSE},
        layout as received_layout,
    };
    use topo::protocol::connection::bootstrap_request::create::encode_optional_addr;
    use topo::protocol::connection::bootstrap_request::{
        fact::BootstrapRequestFact, layout as request_layout,
    };
    use topo::protocol::connection::bootstrap_response::{create, layout, project, rows};
    use topo::protocol::sync::seed_connection::SEED_CONNECTION_SYNC;

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
    fn response_missing_request_waits_without_row() {
        let scenario = scenario();
        let context = ProjectionContext::from_matches(vec![
            invite_match(scenario.response_fact.id, scenario.invite_fact),
            ephemeral_match(scenario.response_fact.id, scenario.responder_ephemeral_fact),
        ]);

        let output = project::BootstrapResponseProjector::new()
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

        let output = project::BootstrapResponseProjector::new()
            .project(&scenario.response_fact, &context)
            .expect("project response");

        assert!(output.effects.intents.is_empty());
        assert!(output.time_wakes.is_empty());
        assert_eq!(output.effects.row_mutations.len(), 1);
        let RowMutation::PutRow(row) = &output.effects.row_mutations[0] else {
            panic!("expected put row mutation");
        };
        let response = layout::decode_fact(&scenario.response_fact.bytes).expect("decode response");
        let row = rows::decode_bootstrap_response_row(&row.key, &row.value)
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
        assert!(output
            .offers
            .iter()
            .any(|offer| offer.role == "connection_response_for_request"
                && offer.start_key.as_bytes() == &scenario.request_fact.id[..]
                && offer.end_key.as_bytes() == &scenario.request_fact.id[..]));
    }

    #[test]
    fn local_response_does_not_seed_bootstrap_sync() {
        let scenario = scenario();
        let context = ProjectionContext::from_matches(vec![
            request_match(scenario.response_fact.id, scenario.request_fact.clone()),
            invite_match(scenario.response_fact.id, scenario.invite_fact.clone()),
            ephemeral_match(
                scenario.response_fact.id,
                scenario.responder_ephemeral_fact.clone(),
            ),
        ]);

        let output = project::BootstrapResponseProjector::new()
            .project(&scenario.response_fact, &context)
            .expect("project response");

        assert!(output.effects.intents.is_empty());
        assert!(output.time_wakes.is_empty());
    }

    #[test]
    fn received_response_materializes_after_receipt_and_initiator_ephemeral_context() {
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

        let output = project::BootstrapResponseProjector::new()
            .project(&scenario.response_fact, &context)
            .expect("project received response");

        assert_eq!(output.effects.intents.len(), 1);
        assert_eq!(
            output.effects.intents[0].kind.as_str(),
            SEED_CONNECTION_SYNC
        );
        assert!(output.time_wakes.is_empty());
        assert_eq!(output.effects.row_mutations.len(), 1);
        let RowMutation::PutRow(row) = &output.effects.row_mutations[0] else {
            panic!("expected put row mutation");
        };
        let row = rows::decode_bootstrap_response_row(&row.key, &row.value)
            .expect("decode connection response row");
        assert_eq!(row.connection_id, scenario.response_fact.id);
        assert_eq!(row.to_endpoint, response.to_endpoint);
        assert!(output
            .offers
            .iter()
            .any(|offer| offer.role == "connection_response_for_request"
                && offer.start_key.as_bytes() == &scenario.request_fact.id[..]
                && offer.end_key.as_bytes() == &scenario.request_fact.id[..]));
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
