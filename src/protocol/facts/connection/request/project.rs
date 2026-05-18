//! Poc-10 connection-request projector.
//!
//! POLICY. A connection_request is admitted iff:
//!   1. STRUCTURAL. The fact is local or global, the request fields are
//!      non-empty, and the endpoints differ.
//!   2. CONTEXT. Both branches require invite-secret context. Local requests
//!      require initiator ephemeral-secret context; received requests require
//!      transit receive provenance addressed to this endpoint.
//!   3. MATERIALIZE. Valid requests write the request row and offer request
//!      context; received bootstrap requests also emit deferred response work.

use crate::core::crypto;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use crate::protocol::facts::connection::ephemeral_secret;
use crate::protocol::facts::identity::invite;
use crate::protocol::facts::transport::transit_received;
use crate::protocol::intents::connection::create_response::{
    create_connection_response_intent, CreateConnectionResponse,
};
use crate::protocol::matchers;
use crate::protocol::matchers as ephemeral_matchers;
use crate::protocol::matchers as receive_matchers;

use super::addr::encode_optional_addr;
use super::fact::ConnectionRequestFact;
use super::rows::connection_request_row;

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
        project_typed::<super::Codec, _>(self, fact, projection_context)
    }
}

impl TypedProjector<super::Codec> for ConnectionRequestProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        request: ConnectionRequestFact,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if !matches!(fact.scope, FactScope::Local | FactScope::Global) {
            return Err("connection request fact must be local or global".to_string());
        }
        validate_request_fields(&request)?;
        if request.from_endpoint == request.to_endpoint {
            return Err("connection request endpoints must differ".to_string());
        }

        // 2. Shared invite context.
        let invite_need =
            matchers::connection_invite_secret_need(fact.id, request.invite_secret_fact_id);
        let Some(invite) = projection_context.payload_for(&invite_need) else {
            return Ok(waiting_output([invite_need]));
        };
        let invite_secret = invite::decode_fact_payload(&invite.bytes)
            .map_err(|_| "connection request invite context is not an invite secret".to_string())?;
        if invite.id != request.invite_secret_fact_id {
            return Err("connection request invite context id does not match request".to_string());
        }
        if invite.scope != FactScope::Local {
            return Err("connection request invite context must be local".to_string());
        }
        validate_invite_signature(&request, &invite_secret)?;

        if fact.scope == FactScope::Local {
            // 2a. Local send path.
            let ephemeral_need = ephemeral_matchers::connection_ephemeral_secret_need(
                fact.id,
                request.initiator_ephemeral_secret_fact_id,
            );
            let Some(ephemeral) = projection_context.payload_for(&ephemeral_need) else {
                return Ok(waiting_output([invite_need, ephemeral_need]));
            };
            let ephemeral_secret = ephemeral_secret::decode_fact_payload(&ephemeral.bytes)
                .map_err(|_| {
                    "connection request dependency is not an ephemeral secret".to_string()
                })?;
            if ephemeral.id != request.initiator_ephemeral_secret_fact_id {
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
            // 3. Materialize local request.
            return materialized_output(fact.id, &request);
        }

        // 2b. Received bootstrap path.
        let receive_need = receive_matchers::transit_received_need(fact.id, fact.id);
        let Some(receive) = projection_context
            .matched_payloads_for(&receive_need)
            .map(|(_, fact)| fact)
            .min_by_key(|fact| fact.id)
        else {
            return Ok(waiting_output([invite_need, receive_need]));
        };
        if receive.scope != FactScope::Local {
            return Err("connection request receive context must be local".to_string());
        }
        let received = transit_received::decode_fact_payload(receive.body()).map_err(|_| {
            "connection request receive context is not transport::transit provenance".to_string()
        })?;
        if received.received_fact_id != fact.id {
            return Err("connection request receive context targets another fact".to_string());
        }
        if received.transit_kind
            != crate::protocol::facts::transport::transit_received::fact::TRANSIT_KIND_BOOTSTRAP
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
        if request.from_listen_addr.is_none() {
            return Err("connection request bootstrap response route is missing".to_string());
        }

        // 3. Materialize received request and schedule response creation.
        received_materialized_output(fact.id, &request, receive.id)
    }
}

fn validate_request_fields(request: &ConnectionRequestFact) -> Result<(), String> {
    if request.from_endpoint == [0; 32] {
        return Err("connection request from_endpoint cannot be empty".to_string());
    }
    if request.to_endpoint == [0; 32] {
        return Err("connection request to_endpoint cannot be empty".to_string());
    }
    if request.invite_fact_id == [0; 32] {
        return Err("connection request invite_fact_id cannot be empty".to_string());
    }
    if request.bootstrap_hash == [0; 32] {
        return Err("connection request bootstrap_hash cannot be empty".to_string());
    }
    if request.invite_secret_fact_id == [0; 32] {
        return Err("connection request invite_secret_fact_id cannot be empty".to_string());
    }
    if request.initiator_ephemeral_secret_fact_id == [0; 32] {
        return Err(
            "connection request initiator_ephemeral_secret_fact_id cannot be empty".to_string(),
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

fn received_materialized_output(
    request_id: [u8; 32],
    request: &ConnectionRequestFact,
    receive_id: [u8; 32],
) -> Result<ProjectionOutput, String> {
    Ok(
        materialized_output(request_id, request)?.intent(create_connection_response_intent(
            CreateConnectionResponse {
                request_id,
                invite_secret_id: request.invite_secret_fact_id,
                receive_id,
            },
        )),
    )
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
    invite_secret: &crate::protocol::facts::identity::invite::fact::InviteSecretFact,
) -> Result<(), String> {
    if invite_secret.bootstrap_hash != request.bootstrap_hash {
        return Err("connection request bootstrap hash is not authorized".to_string());
    }
    if let Some(invite_fact_id) = invite_secret.invite_fact_id {
        if invite_fact_id != request.invite_fact_id {
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
    out.extend_from_slice(&request.invite_fact_id);
    out.extend_from_slice(&request.bootstrap_hash);
    out.extend_from_slice(&request.invite_secret_fact_id);
    out.extend_from_slice(&request.initiator_ephemeral_secret_fact_id);
    out.extend_from_slice(&request.initiator_ephemeral_public_key);
    out.extend_from_slice(&encode_optional_addr(request.from_listen_addr)?);
    out.extend_from_slice(&encode_optional_addr(request.to_listen_addr)?);
    Ok(out)
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::crypto::{self, ED25519_SIGNATURE_BYTES};
    use topo::core::facts::{Fact, FactScope};
    use topo::core::intents::AtomicIntent;
    use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
    use topo::protocol::facts::connection::ephemeral_secret::{
        fact::ConnectionEphemeralSecretFact, layout as ephemeral_layout,
    };
    use topo::protocol::facts::connection::request::{
        addr::encode_optional_addr, fact::ConnectionRequestFact, layout, project, rows,
    };
    use topo::protocol::facts::identity::invite::{
        fact::InviteSecretFact, layout as invite_layout,
    };
    use topo::protocol::facts::transport::transit_received::{
        fact::{TransitReceivedFact, TRANSIT_KIND_BOOTSTRAP},
        layout as received_layout,
    };
    use topo::protocol::intents::connection::create_response::{
        decode_create_connection_response_intent, CREATE_CONNECTION_RESPONSE,
    };
    use topo::protocol::matchers as ephemeral_matchers;
    use topo::protocol::matchers as received_matchers;
    use topo::protocol::matchers as request_matchers;

    fn invite_fact() -> (InviteSecretFact, Fact) {
        let invite = InviteSecretFact::new([55; 32]);
        let fact = Fact::new(
            FactScope::Local,
            10,
            invite_layout::encode_fact(&invite).expect("encode invite"),
        );
        (invite, fact)
    }

    fn ephemeral_fact(owner_endpoint: [u8; 32]) -> (ConnectionEphemeralSecretFact, Fact) {
        let private_key = [7u8; 32];
        let secret = ConnectionEphemeralSecretFact {
            owner_endpoint,
            ephemeral_private_key: private_key,
            ephemeral_public_key: crypto::x25519_public_key(&private_key),
            created_at_ms: 11,
        };
        let fact = Fact::new(
            FactScope::Local,
            11,
            ephemeral_layout::encode_fact(&secret).expect("encode ephemeral"),
        );
        (secret, fact)
    }

    fn signed_request_fact(scope: FactScope) -> (ConnectionRequestFact, Fact, Fact, Fact) {
        let (invite, invite_fact) = invite_fact();
        let (ephemeral, ephemeral_fact) = ephemeral_fact([1; 32]);
        let mut request = ConnectionRequestFact {
            from_endpoint: [1; 32],
            to_endpoint: [2; 32],
            nonce: [3; 32],
            invite_fact_id: [4; 32],
            bootstrap_hash: invite.bootstrap_hash,
            invite_signature: [0; ED25519_SIGNATURE_BYTES],
            invite_secret_fact_id: invite_fact.id,
            initiator_ephemeral_secret_fact_id: ephemeral_fact.id,
            initiator_ephemeral_public_key: ephemeral.ephemeral_public_key,
            from_listen_addr: Some("127.0.0.1:41001".parse().expect("listen addr")),
            to_listen_addr: None,
        };
        request.invite_signature = crypto::ed25519_sign(
            &invite.bootstrap_secret,
            &invite_signing_transcript(&request).expect("transcript"),
        );
        let request_fact = Fact::new(
            scope,
            12,
            layout::encode_fact(&request).expect("encode request"),
        );
        (request, request_fact, invite_fact, ephemeral_fact)
    }

    fn invite_match(owner: [u8; 32], invite: Fact) -> MatchedContext {
        let need = request_matchers::connection_invite_secret_need(owner, invite.id);
        MatchedContext {
            need: need.clone(),
            offer: request_matchers::connection_invite_secret_offer(invite.id, invite.id),
            payload: invite,
        }
    }

    fn ephemeral_match(owner: [u8; 32], ephemeral: Fact) -> MatchedContext {
        let need = ephemeral_matchers::connection_ephemeral_secret_need(owner, ephemeral.id);
        MatchedContext {
            need,
            offer: ephemeral_matchers::connection_ephemeral_secret_offer(
                ephemeral.id,
                ephemeral.id,
            ),
            payload: ephemeral,
        }
    }

    fn receive_match(
        owner: [u8; 32],
        request: &ConnectionRequestFact,
        request_id: [u8; 32],
        received_at_local_ms: u64,
    ) -> MatchedContext {
        let received = TransitReceivedFact {
            received_fact_id: request_id,
            origin_addr: b"127.0.0.1:41001".to_vec(),
            local_endpoint_id: request.to_endpoint,
            sender_endpoint_id: request.from_endpoint,
            transit_kind: TRANSIT_KIND_BOOTSTRAP,
            connection_id: None,
            request_id: Some(request_id),
            frame_hash: [9; 32],
            received_at_local_ms,
        };
        let fact = Fact::new(
            FactScope::Local,
            13,
            received_layout::encode_fact(&received).expect("encode provenance"),
        );
        let need = received_matchers::transit_received_need(owner, request_id);
        MatchedContext {
            need,
            offer: received_matchers::transit_received_offer(fact.id, request_id),
            payload: fact,
        }
    }

    #[test]
    fn local_request_missing_ephemeral_waits_without_row() {
        let (_, request_fact, invite_fact, _) = signed_request_fact(FactScope::Local);
        let context =
            ProjectionContext::from_matches(vec![invite_match(request_fact.id, invite_fact)]);

        let output = project::ConnectionRequestProjector::new()
            .project(&request_fact, &context)
            .expect("project waits");

        assert!(output.intents.is_empty());
        assert_eq!(output.needs.len(), 2);
        assert!(
            output
                .needs
                .iter()
                .any(|need| need.role.as_str()
                    == ephemeral_matchers::CONNECTION_EPHEMERAL_SECRET_ROLE)
        );
    }

    #[test]
    fn received_request_missing_provenance_waits_without_row() {
        let (_, request_fact, invite_fact, _) = signed_request_fact(FactScope::Global);
        let context =
            ProjectionContext::from_matches(vec![invite_match(request_fact.id, invite_fact)]);

        let output = project::ConnectionRequestProjector::new()
            .project(&request_fact, &context)
            .expect("project waits");

        assert!(output.intents.is_empty());
        assert_eq!(output.needs.len(), 2);
        assert!(output
            .needs
            .iter()
            .any(|need| need.role == received_matchers::transit_received_role()));
    }

    #[test]
    fn local_request_materializes_after_invite_and_ephemeral_context_match() {
        let (request, request_fact, invite_fact, ephemeral_fact) =
            signed_request_fact(FactScope::Local);
        let context = ProjectionContext::from_matches(vec![
            invite_match(request_fact.id, invite_fact),
            ephemeral_match(request_fact.id, ephemeral_fact),
        ]);

        let output = project::ConnectionRequestProjector::new()
            .project(&request_fact, &context)
            .expect("project request");

        assert_eq!(output.intents.len(), 1);
        assert_eq!(output.offers.len(), 1);
        assert_eq!(
            output.offers[0].role.as_str(),
            request_matchers::CONNECTION_REQUEST_ROLE
        );
        let AtomicIntent::PutRow(row) =
            AtomicIntent::from_intent(&output.intents[0], &[rows::CONNECTION_REQUEST_ROWS])
                .expect("row intent")
        else {
            panic!("expected put_row intent");
        };
        let row = rows::decode_connection_request_row(&row.key, &row.value)
            .expect("decode connection request row");
        assert_eq!(row.request_id, request_fact.id);
        assert_eq!(row.from_endpoint, request.from_endpoint);
        assert_eq!(row.to_endpoint, request.to_endpoint);
        assert_eq!(row.invite_fact_id, request.invite_fact_id);
        assert_eq!(row.invite_secret_fact_id, request.invite_secret_fact_id);
        assert_eq!(
            row.initiator_ephemeral_secret_fact_id,
            request.initiator_ephemeral_secret_fact_id
        );
    }

    #[test]
    fn received_request_materializes_after_invite_and_provenance_context_match() {
        let (request, request_fact, invite_fact, _) = signed_request_fact(FactScope::Global);
        let context = ProjectionContext::from_matches(vec![
            invite_match(request_fact.id, invite_fact),
            receive_match(request_fact.id, &request, request_fact.id, 1_700_000_000),
        ]);

        let output = project::ConnectionRequestProjector::new()
            .project(&request_fact, &context)
            .expect("project received request");

        assert_eq!(output.intents.len(), 2);
        assert_eq!(
            output.offers[0].role.as_str(),
            request_matchers::CONNECTION_REQUEST_ROLE
        );
        let response_intent = output
            .intents
            .iter()
            .find(|intent| intent.kind.as_str() == CREATE_CONNECTION_RESPONSE)
            .expect("create response intent");
        let decoded =
            decode_create_connection_response_intent(response_intent).expect("decode intent");
        assert_eq!(decoded.request_id, request_fact.id);
        assert_eq!(decoded.invite_secret_id, request.invite_secret_fact_id);
    }

    #[test]
    fn received_request_duplicate_provenance_emits_one_response_intent() {
        let (request, request_fact, invite_fact, _) = signed_request_fact(FactScope::Global);
        let context = ProjectionContext::from_matches(vec![
            invite_match(request_fact.id, invite_fact),
            receive_match(request_fact.id, &request, request_fact.id, 1_700_000_000),
            receive_match(request_fact.id, &request, request_fact.id, 1_700_000_250),
        ]);

        let output = project::ConnectionRequestProjector::new()
            .project(&request_fact, &context)
            .expect("project received request");

        let response_intents = output
            .intents
            .iter()
            .filter(|intent| intent.kind.as_str() == CREATE_CONNECTION_RESPONSE)
            .collect::<Vec<_>>();
        assert_eq!(
            response_intents.len(),
            1,
            "duplicate receive provenance for one request must collapse to one response intent"
        );
    }

    #[test]
    fn connection_request_projector_rejects_self_loop() {
        let (mut request, _, _, _) = signed_request_fact(FactScope::Local);
        request.to_endpoint = request.from_endpoint;
        let fact = Fact::new(
            FactScope::Local,
            0,
            layout::encode_fact(&request).expect("encode request"),
        );
        let err = project::ConnectionRequestProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect_err("self-loop request must fail projection");
        assert!(err.contains("endpoints"), "{err}");
    }

    #[test]
    fn connection_request_projector_rejects_malformed_bytes() {
        let fact = Fact::new(FactScope::Local, 0, vec![0; 4]);
        let err = project::ConnectionRequestProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect_err("malformed bytes must fail projection");
        assert!(
            err.contains("connection request") || err.contains("Length"),
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
