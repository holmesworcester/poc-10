//! Connection-request projector.
//!
//! Request projection validates a received durable semantic handshake request.
//! Local sender-side state is recorded by `bootstrap_request_sent`; this
//! projector only handles the responder path after the bootstrap wrapper has
//! opened sealed bytes into this canonical `bootstrap_request` fact.
//!
//! POLICY. A connection_request is admitted iff:
//!   1. STRUCTURAL. The fact is received/global, the request fields are
//!      non-empty, and the endpoints differ.
//!   2. CONTEXT. Projection requires invite-secret, local-endpoint, and
//!      connection fact-receipt context addressed to that endpoint.
//!   3. MATERIALIZE. Valid requests offer request context, emit
//!      `bootstrap_request_received`, emit deferred response work, and learn the
//!      initiator's reachable address.
//!
//! Change this projector for request admission, branch-specific context proofs,
//! peer-retry behavior, or materialized request rows. Bootstrap wrapper opening
//! belongs in `bootstrap_request::project`, request byte layout belongs in
//! `layout.rs`, and response construction belongs in `create_bootstrap_response.rs` plus
//! `response::create`.

use crate::core::crypto;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::projectors::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
};

use crate::protocol::auth::{endpoint, invite};
use crate::protocol::connection::bootstrap_request_received;
use crate::protocol::connection::bootstrap_request_received::fact::BootstrapRequestReceivedFact;
use crate::protocol::connection::create_bootstrap_response::{
    create_bootstrap_response_intent, CreateBootstrapResponse,
};
use crate::protocol::connection::fact_receipt;
use crate::protocol::connection::observed_endpoint_address::rows::observed_endpoint_address_row;

use super::create::encode_optional_addr;
use super::fact::BootstrapRequestFact;

const CONNECTION_RESPONSE_FOR_REQUEST_ROLE: &str = "connection_response_for_request";

pub fn connection_response_for_request_need(
    owner: crate::core::facts::FactId,
    request_id: crate::core::facts::FactId,
) -> crate::core::context::ContextNeed {
    crate::core::context::ContextNeed::range(
        owner,
        crate::core::context::Role::expect(CONNECTION_RESPONSE_FOR_REQUEST_ROLE),
        crate::core::facts::FactScope::Local,
        request_id,
        request_id,
    )
}

pub fn connection_response_for_request_offer(
    owner: crate::core::facts::FactId,
    request_id: crate::core::facts::FactId,
) -> crate::core::context::ContextOffer {
    crate::core::context::ContextOffer::range(
        owner,
        crate::core::context::Role::expect(CONNECTION_RESPONSE_FOR_REQUEST_ROLE),
        crate::core::facts::FactScope::Local,
        request_id,
        request_id,
    )
}

#[derive(Debug, Clone, Default)]
pub struct BootstrapRequestProjector;

impl BootstrapRequestProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for BootstrapRequestProjector {
    fn project(
        &self,
        fact: &Fact,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_authenticated::<super::authenticate::BootstrapRequestAuthenticator, _>(
            self,
            fact,
            projection_context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::BootstrapRequestAuthenticator>
    for BootstrapRequestProjector
{
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, BootstrapRequestFact>,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // Authentication (see authenticate.rs) proved canonical bytes and the
        // intrinsic request fields. Scope is interpretation.
        let (fact, request) = authenticated.into_parts();
        // 1. Scope.
        if fact.scope != FactScope::Global {
            return Err("bootstrap request fact must be received/global".to_string());
        }

        // 2. Shared invite context.
        let invite_need = crate::core::context::ContextNeed::range(
            fact.id,
            "connection_invite_secret",
            crate::core::facts::FactScope::Local,
            request.invite_secret_fact_id,
            request.invite_secret_fact_id,
        );
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

        // 2. Received semantic request path.
        let endpoint_need = crate::core::context::ContextNeed::range(
            fact.id,
            "auth_local_endpoint",
            crate::core::facts::FactScope::Local,
            request.to_endpoint,
            request.to_endpoint,
        );
        let receive_need = crate::core::context::ContextNeed::range(
            fact.id,
            "connection_fact_receipt",
            crate::core::facts::FactScope::Local,
            fact.id,
            fact.id,
        );
        let Some(endpoint_context) = projection_context.payload_for(&endpoint_need) else {
            return Ok(waiting_output([invite_need, endpoint_need, receive_need]));
        };
        if endpoint_context.scope != FactScope::Local {
            return Err("connection request endpoint context must be local".to_string());
        }
        let local_endpoint =
            endpoint::decode_fact_payload(endpoint_context.body()).map_err(|_| {
                "connection request endpoint context is not a local endpoint".to_string()
            })?;
        if local_endpoint.endpoint != request.to_endpoint {
            return Err("connection request endpoint context does not match request".to_string());
        }
        let Some(receive) = projection_context
            .matched_payloads_for(&receive_need)
            .map(|(_, fact)| fact)
            .min_by_key(|fact| fact.id)
        else {
            return Ok(waiting_output([invite_need, endpoint_need, receive_need]));
        };
        if receive.scope != FactScope::Local {
            return Err("connection request receive context must be local".to_string());
        }
        let received = fact_receipt::decode_fact_payload(receive.body()).map_err(|_| {
            "connection request receive context is not connection fact receipt".to_string()
        })?;
        if received.received_fact_id != fact.id {
            return Err("connection request receive context targets another fact".to_string());
        }
        if received.receive_path
            != crate::protocol::connection::fact_receipt::fact::RECEIVE_PATH_CONNECTION_REQUEST
        {
            return Err("connection request requires connection request receipt".to_string());
        }
        if received.local_endpoint_id != request.to_endpoint {
            return Err("connection request addressed to a different endpoint".to_string());
        }
        if received.sender_endpoint_id != request.from_endpoint {
            return Err("connection request sender does not match receive sender".to_string());
        }
        if let Some(request_id) = received.request_id {
            if request_id != fact.id {
                return Err("connection request fact receipt names another request".to_string());
            }
        }
        if request.from_listen_addr.is_none() {
            return Err("connection request bootstrap response route is missing".to_string());
        }

        // 3. Materialize received request and schedule response creation.
        received_materialized_output(fact.id, &request, receive.id, received.received_at_local_ms)
    }
}

fn received_materialized_output(
    request_id: [u8; 32],
    request: &BootstrapRequestFact,
    receive_id: [u8; 32],
    received_at_local_ms: u64,
) -> Result<ProjectionOutput, String> {
    let received_fact = Fact::new(
        FactScope::Local,
        received_at_local_ms,
        bootstrap_request_received::layout::encode_fact(&BootstrapRequestReceivedFact {
            request_id,
            receive_id,
            received_at_local_ms,
        })?,
    );
    let mut output = ProjectionOutput::new()
        .offer(crate::core::context::ContextOffer::range(
            request_id,
            "connection_request",
            crate::core::facts::FactScope::Global,
            request_id,
            request_id,
        ))
        .fact(received_fact)
        .intent(create_bootstrap_response_intent(CreateBootstrapResponse {
            request_id,
            invite_secret_id: request.invite_secret_fact_id,
            receive_id,
        }));
    // Learn the initiator's reachable listen address from the received request,
    // so we can later open a membership connection back to it without an invite.
    if let Some(addr) = request.from_listen_addr {
        output = output.row_mutation(RowMutation::PutRow(observed_endpoint_address_row(
            request.from_endpoint,
            addr,
        )?));
    }
    Ok(output)
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
    request: &BootstrapRequestFact,
    invite_secret: &crate::protocol::auth::invite::fact::InviteSecretFact,
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

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::crypto::{self, ED25519_SIGNATURE_BYTES};
    use topo::core::facts::{Fact, FactScope};
    use topo::core::intents::RowMutation;
    use topo::core::projectors::ProjectionOutput;
    use topo::protocol::connection::observed_endpoint_address::rows::{
        observed_endpoint_address_key, CONNECTION_OBSERVED_ENDPOINT_ADDRESS_ROWS,
    };

    /// Whether the projection learned a reachable address for `endpoint`.
    fn learns_observed_endpoint_address(output: &ProjectionOutput, endpoint: [u8; 32]) -> bool {
        output.effects.row_mutations.iter().any(|mutation| {
            matches!(
                mutation,
                RowMutation::PutRow(row)
                    if row.table == CONNECTION_OBSERVED_ENDPOINT_ADDRESS_ROWS
                        && row.key == observed_endpoint_address_key(&endpoint)
            )
        })
    }
    use topo::core::projectors::{MatchedContext, ProjectionContext, Projector};
    use topo::protocol::auth::endpoint::{fact::EndpointFact, layout as endpoint_layout};
    use topo::protocol::auth::invite::{fact::InviteSecretFact, layout as invite_layout};
    use topo::protocol::connection::bootstrap_request::create::encode_optional_addr;
    use topo::protocol::connection::bootstrap_request::{
        fact::BootstrapRequestFact, layout, project,
    };
    use topo::protocol::connection::bootstrap_request_received::layout as request_received_layout;
    use topo::protocol::connection::create_bootstrap_response::{
        decode_create_bootstrap_response_intent, CREATE_BOOTSTRAP_RESPONSE,
    };
    use topo::protocol::connection::ephemeral_secret::{
        fact::ConnectionEphemeralSecretFact, layout as ephemeral_layout,
    };
    use topo::protocol::connection::fact_receipt::{
        fact::{ConnectionFactReceipt, RECEIVE_PATH_CONNECTION_REQUEST},
        layout as received_layout,
    };

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

    fn signed_request_fact(scope: FactScope) -> (BootstrapRequestFact, Fact, Fact, Fact) {
        let (invite, invite_fact) = invite_fact();
        let (ephemeral, ephemeral_fact) = ephemeral_fact([1; 32]);
        let mut request = BootstrapRequestFact {
            from_endpoint: [1; 32],
            to_endpoint: crypto::x25519_public_key(&[2; 32]),
            nonce: [3; 32],
            invite_fact_id: [4; 32],
            bootstrap_hash: invite.bootstrap_hash,
            invite_signature: [0; ED25519_SIGNATURE_BYTES],
            invite_secret_fact_id: invite_fact.id,
            initiator_ephemeral_secret_fact_id: ephemeral_fact.id,
            initiator_ephemeral_public_key: ephemeral.ephemeral_public_key,
            from_listen_addr: Some("127.0.0.1:41001".parse().expect("listen addr")),
            to_listen_addr: Some("127.0.0.1:41002".parse().expect("remote addr")),
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
        let need = crate::core::context::ContextNeed::range(
            owner,
            "connection_invite_secret",
            crate::core::facts::FactScope::Local,
            invite.id,
            invite.id,
        );
        MatchedContext {
            need: need.clone(),
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

    fn receive_match(
        owner: [u8; 32],
        request: &BootstrapRequestFact,
        request_id: [u8; 32],
        received_at_local_ms: u64,
    ) -> MatchedContext {
        let received = ConnectionFactReceipt {
            received_fact_id: request_id,
            origin_addr: crate::protocol::connection::fact_receipt::fact::OriginAddr::new(
                b"127.0.0.1:41001",
            )
            .expect("origin"),
            local_endpoint_id: request.to_endpoint,
            sender_endpoint_id: request.from_endpoint,
            receive_path: RECEIVE_PATH_CONNECTION_REQUEST,
            connection_id: None,
            request_id: Some(request_id),
            frame_hash: [9; 32],
            received_at_local_ms,
        };
        let fact = Fact::new(
            FactScope::Local,
            13,
            received_layout::encode_fact(&received).expect("encode receipt"),
        );
        let need = crate::core::context::ContextNeed::range(
            owner,
            "connection_fact_receipt",
            crate::core::facts::FactScope::Local,
            request_id,
            request_id,
        );
        MatchedContext {
            need,
            offer: crate::core::context::ContextOffer::range(
                fact.id,
                "connection_fact_receipt",
                crate::core::facts::FactScope::Local,
                request_id,
                request_id,
            ),
            payload: fact,
        }
    }

    fn endpoint_match(owner: [u8; 32], endpoint_id: [u8; 32]) -> MatchedContext {
        let endpoint = EndpointFact {
            endpoint: endpoint_id,
            secret: [2; 32],
            signing_public_key: crypto::ed25519_public_key(&[22; 32]),
            signing_secret: [22; 32],
        };
        let fact = Fact::new(
            FactScope::Local,
            14,
            endpoint_layout::encode_fact(&endpoint).expect("encode endpoint"),
        );
        let need = crate::core::context::ContextNeed::range(
            owner,
            "auth_local_endpoint",
            crate::core::facts::FactScope::Local,
            endpoint_id,
            endpoint_id,
        );
        MatchedContext {
            need,
            offer: crate::core::context::ContextOffer::range(
                fact.id,
                "auth_local_endpoint",
                crate::core::facts::FactScope::Local,
                endpoint_id,
                endpoint_id,
            ),
            payload: fact,
        }
    }

    #[test]
    fn local_request_is_not_projected_by_received_request_projector() {
        let (_, request_fact, _, _) = signed_request_fact(FactScope::Local);
        let err = project::BootstrapRequestProjector::new()
            .project(&request_fact, &ProjectionContext::new(Vec::new()))
            .expect_err("local request belongs to bootstrap_request_sent");

        assert!(err.contains("received/global"), "{err}");
    }

    #[test]
    fn received_request_missing_receipt_waits_without_row() {
        let (request, request_fact, invite_fact, _) = signed_request_fact(FactScope::Global);
        let context = ProjectionContext::from_matches(vec![
            invite_match(request_fact.id, invite_fact),
            endpoint_match(request_fact.id, request.to_endpoint),
        ]);

        let output = project::BootstrapRequestProjector::new()
            .project(&request_fact, &context)
            .expect("project waits");

        assert!(output.effects.intents.is_empty());
        assert_eq!(output.needs.len(), 3);
        assert!(output
            .needs
            .iter()
            .any(|need| need.role == "connection_fact_receipt"));
    }

    #[test]
    fn received_request_materializes_after_invite_and_receipt_context_match() {
        let (request, request_fact, invite_fact, _) = signed_request_fact(FactScope::Global);
        let context = ProjectionContext::from_matches(vec![
            invite_match(request_fact.id, invite_fact),
            endpoint_match(request_fact.id, request.to_endpoint),
            receive_match(request_fact.id, &request, request_fact.id, 1_700_000_000),
        ]);

        let output = project::BootstrapRequestProjector::new()
            .project(&request_fact, &context)
            .expect("project received request");

        assert_eq!(output.effects.intents.len(), 1);
        assert!(output.effects.local_intents.is_empty());
        assert!(output.time_wakes.is_empty());
        assert_eq!(output.effects.facts.len(), 1);
        let received = request_received_layout::decode_fact(output.effects.facts[0].body())
            .expect("decode request received lifecycle");
        assert_eq!(received.request_id, request_fact.id);
        assert_eq!(received.received_at_local_ms, 1_700_000_000);
        assert_eq!(output.effects.row_mutations.len(), 1);
        assert!(learns_observed_endpoint_address(
            &output,
            request.from_endpoint
        ));
        assert_eq!(output.offers[0].role.as_str(), "connection_request");
        let response_intent = output
            .effects
            .intents
            .iter()
            .find(|intent| intent.kind.as_str() == CREATE_BOOTSTRAP_RESPONSE)
            .expect("create response intent");
        let decoded =
            decode_create_bootstrap_response_intent(response_intent).expect("decode intent");
        assert_eq!(decoded.request_id, request_fact.id);
        assert_eq!(decoded.invite_secret_id, request.invite_secret_fact_id);
    }

    #[test]
    fn received_request_never_schedules_bootstrap_send_retry() {
        let (request, request_fact, invite_fact, _) = signed_request_fact(FactScope::Global);
        let context = ProjectionContext::from_matches(vec![
            invite_match(request_fact.id, invite_fact),
            endpoint_match(request_fact.id, request.to_endpoint),
            receive_match(request_fact.id, &request, request_fact.id, 1_700_000_000),
        ]);

        let output = project::BootstrapRequestProjector::new()
            .project(&request_fact, &context)
            .expect("project received request");

        assert!(output.effects.local_intents.is_empty());
        assert!(output.time_wakes.is_empty());
        assert_eq!(
            output
                .effects
                .intents
                .iter()
                .filter(|intent| intent.kind.as_str() == CREATE_BOOTSTRAP_RESPONSE)
                .count(),
            1
        );
    }

    #[test]
    fn received_request_duplicate_receipt_emits_one_response_intent() {
        let (request, request_fact, invite_fact, _) = signed_request_fact(FactScope::Global);
        let context = ProjectionContext::from_matches(vec![
            invite_match(request_fact.id, invite_fact),
            endpoint_match(request_fact.id, request.to_endpoint),
            receive_match(request_fact.id, &request, request_fact.id, 1_700_000_000),
            receive_match(request_fact.id, &request, request_fact.id, 1_700_000_250),
        ]);

        let output = project::BootstrapRequestProjector::new()
            .project(&request_fact, &context)
            .expect("project received request");

        let response_intents = output
            .effects
            .intents
            .iter()
            .filter(|intent| intent.kind.as_str() == CREATE_BOOTSTRAP_RESPONSE)
            .collect::<Vec<_>>();
        assert_eq!(
            response_intents.len(),
            1,
            "duplicate fact receipt for one request must collapse to one response intent"
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
        let err = project::BootstrapRequestProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect_err("self-loop request must fail projection");
        assert!(err.contains("endpoints"), "{err}");
    }

    #[test]
    fn connection_request_projector_rejects_malformed_bytes() {
        let fact = Fact::new(FactScope::Local, 0, vec![0; 4]);
        let err = project::BootstrapRequestProjector::new()
            .project(&fact, &ProjectionContext::new(Vec::new()))
            .expect_err("malformed bytes must fail projection");
        assert!(
            err.contains("connection request") || err.contains("Length"),
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
