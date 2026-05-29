//! Connection-request projector.
//!
//! Request projection validates the durable semantic handshake request. Local
//! requests prove invite-secret and initiator ephemeral-secret context, then
//! materialize and register a connection-maintenance candidate so the live
//! maintenance loop can attempt bootstrap sends. Received requests prove
//! invite-secret, local endpoint, and fact-receipt context after the bootstrap
//! wrapper has already opened those bytes into this canonical
//! `connection_request` fact.
//!
//! POLICY. A connection_request is admitted iff:
//!   1. STRUCTURAL. The fact is local or global, the request fields are
//!      non-empty, and the endpoints differ.
//!   2. CONTEXT. Both branches require invite-secret context. Local requests
//!      require initiator ephemeral-secret context; received requests require
//!      local-endpoint context plus connection fact receipt addressed to
//!      that endpoint.
//!   3. MATERIALIZE. Valid requests write the request row and offer request
//!      context. A local request with a reachable route registers a
//!      connection-maintenance candidate while it is unanswered and unregisters
//!      it once a response appears; received requests emit deferred response
//!      work.
//!
//! This projector does not own an operational retry loop and emits no time
//! wakes. Bootstrap sends are live attempts created by `maintain_connections`
//! from the candidate index. Change this projector for request admission,
//! branch-specific context proofs, candidate registration, or materialized
//! request rows. Bootstrap wrapper opening belongs in
//! `bootstrap_request::project`, request byte layout belongs in `layout.rs`, and
//! response construction belongs in `create_connection_response.rs` plus
//! `response::create`.

use crate::core::context::ContextNeed;
use crate::core::crypto;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use crate::protocol::auth::{endpoint, invite};
use crate::protocol::connection::create_connection_response::{
    create_connection_response_intent, CreateConnectionResponse,
};
use crate::protocol::connection::ephemeral_secret;
use crate::protocol::connection::fact_receipt;

use super::create::encode_optional_addr;
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

        if fact.scope == FactScope::Local {
            // 2a. Local send path.
            let ephemeral_need = crate::core::context::ContextNeed::range(
                fact.id,
                "connection_ephemeral_secret",
                crate::core::facts::FactScope::Local,
                request.initiator_ephemeral_secret_fact_id,
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
            // 3. Materialize the local outbound request. Its row carries the
            // bootstrap route (its `to_listen_addr`), which is what makes it a
            // pending bootstrap candidate for the live maintenance query until a
            // response materializes. When the response context appears, the row
            // stays (the connection response row marks it answered), and the
            // standing response need is dropped.
            let response_need =
                crate::protocol::connection::request::connection_response_for_request_need(
                    fact.id, fact.id,
                );
            if let Some(response_fact) = projection_context.payload_for(&response_need) {
                if response_fact.scope != FactScope::Local {
                    return Err("connection request response context must be local".to_string());
                }
                let response = crate::protocol::connection::response::decode_fact_payload(
                    response_fact.body(),
                )
                .map_err(|_| {
                    "connection request response context is not a response fact".to_string()
                })?;
                if response.request_id != fact.id {
                    return Err(
                        "connection request response context targets another request".to_string(),
                    );
                }
                return materialized_output(fact.id, &request, true);
            }
            return local_pending_output(fact, &request, response_need);
        }

        // 2b. Received semantic request path.
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

/// Materialize a request row and offer request context.
///
/// `bootstrap_addr` is the local outbound route: `Some(addr)` for a local
/// request that should be bootstrapped to `addr`, `None` for a received request
/// or a local request with no route. It is projected into the row so the live
/// maintenance query can select pending bootstraps without re-reading the fact.
fn materialized_output(
    request_id: [u8; 32],
    request: &ConnectionRequestFact,
    local_outbound: bool,
) -> Result<ProjectionOutput, String> {
    // Only a local outbound request projects a bootstrap route into its row; a
    // received request is answered, not bootstrapped.
    let bootstrap_addr = if local_outbound {
        request.to_listen_addr
    } else {
        None
    };
    Ok(ProjectionOutput::new()
        .offer(crate::core::context::ContextOffer::range(
            request_id,
            "connection_request",
            crate::core::facts::FactScope::Global,
            request_id,
            request_id,
        ))
        .row_mutation(RowMutation::PutRow(connection_request_row(
            request_id,
            request,
            bootstrap_addr,
        )?)))
}

/// Materialize an unanswered local request.
///
/// The row carries the bootstrap route (`to_listen_addr`), so it is selected by
/// the live `maintain_connections` query as a pending bootstrap until a response
/// materializes. The request keeps its standing need for the response. The
/// projector owns no retry loop and emits no time wake: bootstrap sends are live
/// operational work owned by `maintain_connections`.
fn local_pending_output(
    fact: &Fact,
    request: &ConnectionRequestFact,
    response_need: ContextNeed,
) -> Result<ProjectionOutput, String> {
    Ok(materialized_output(fact.id, request, true)?.need(response_need))
}

fn received_materialized_output(
    request_id: [u8; 32],
    request: &ConnectionRequestFact,
    receive_id: [u8; 32],
) -> Result<ProjectionOutput, String> {
    // A received request is not a local outbound bootstrap, so its row carries no
    // bootstrap route.
    Ok(
        materialized_output(request_id, request, false)?.intent(create_connection_response_intent(
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
    use topo::core::intents::RowMutation;
    use topo::core::projectors::{MatchedContext, ProjectionContext, Projector};
    use topo::protocol::auth::endpoint::{fact::EndpointFact, layout as endpoint_layout};
    use topo::protocol::auth::invite::{fact::InviteSecretFact, layout as invite_layout};
    use topo::protocol::connection::create_connection_response::{
        decode_create_connection_response_intent, CREATE_CONNECTION_RESPONSE,
    };
    use topo::protocol::connection::ephemeral_secret::{
        fact::ConnectionEphemeralSecretFact, layout as ephemeral_layout,
    };
    use topo::protocol::connection::fact_receipt::{
        fact::{ConnectionFactReceipt, RECEIVE_PATH_CONNECTION_REQUEST},
        layout as received_layout,
    };
    use topo::protocol::connection::request::create::encode_optional_addr;
    use topo::protocol::connection::request::{fact::ConnectionRequestFact, layout, project, rows};
    use topo::protocol::connection::response::{
        fact::ConnectionResponseFact, layout as response_layout,
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

    fn signed_request_fact(scope: FactScope) -> (ConnectionRequestFact, Fact, Fact, Fact) {
        let (invite, invite_fact) = invite_fact();
        let (ephemeral, ephemeral_fact) = ephemeral_fact([1; 32]);
        let mut request = ConnectionRequestFact {
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

    fn ephemeral_match(owner: [u8; 32], ephemeral: Fact) -> MatchedContext {
        let need = crate::core::context::ContextNeed::range(
            owner,
            "connection_ephemeral_secret",
            crate::core::facts::FactScope::Local,
            ephemeral.id,
            ephemeral.id,
        );
        MatchedContext {
            need,
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
        request: &ConnectionRequestFact,
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

    fn response_match(owner: [u8; 32], request_id: [u8; 32]) -> MatchedContext {
        let response = ConnectionResponseFact {
            from_endpoint: [2; 32],
            to_endpoint: [1; 32],
            request_id,
            invite_secret_fact_id: [3; 32],
            initiator_ephemeral_secret_fact_id: [4; 32],
            responder_ephemeral_secret_fact_id: [5; 32],
            responder_ephemeral_public_key: [6; 32],
            handshake_hash: [7; 32],
            connection_secret: [8; 32],
        };
        let fact = Fact::new(
            FactScope::Local,
            15,
            response_layout::encode_fact(&response).expect("encode response"),
        );
        let need = topo::protocol::connection::request::connection_response_for_request_need(
            owner, request_id,
        );
        MatchedContext {
            need,
            offer: topo::protocol::connection::request::connection_response_for_request_offer(
                fact.id, request_id,
            ),
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

        assert!(output.effects.intents.is_empty());
        assert_eq!(output.needs.len(), 2);
        assert!(output
            .needs
            .iter()
            .any(|need| need.role.as_str() == "connection_ephemeral_secret"));
    }

    #[test]
    fn received_request_missing_receipt_waits_without_row() {
        let (request, request_fact, invite_fact, _) = signed_request_fact(FactScope::Global);
        let context = ProjectionContext::from_matches(vec![
            invite_match(request_fact.id, invite_fact),
            endpoint_match(request_fact.id, request.to_endpoint),
        ]);

        let output = project::ConnectionRequestProjector::new()
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
    fn local_request_materializes_with_bootstrap_route_after_context_match() {
        let (request, request_fact, invite_fact, ephemeral_fact) =
            signed_request_fact(FactScope::Local);
        let context = ProjectionContext::from_matches(vec![
            invite_match(request_fact.id, invite_fact),
            ephemeral_match(request_fact.id, ephemeral_fact),
        ]);

        let output = project::ConnectionRequestProjector::new()
            .project(&request_fact, &context)
            .expect("project request");

        // The projector owns no retry loop: no time wake, no send, no candidate
        // intent. It materializes the request row carrying the bootstrap route,
        // which is what the live maintenance query selects on.
        assert!(output.time_wakes.is_empty());
        assert!(output.effects.local_intents.is_empty());
        assert!(output.effects.intents.is_empty());
        assert!(output
            .needs
            .iter()
            .any(|need| need.role == "connection_response_for_request"));
        assert_eq!(output.effects.row_mutations.len(), 1);
        assert_eq!(output.offers.len(), 1);
        assert_eq!(output.offers[0].role.as_str(), "connection_request");
        let RowMutation::PutRow(row) = &output.effects.row_mutations[0] else {
            panic!("expected put row mutation");
        };
        let row = rows::decode_connection_request_row(&row.key, &row.value)
            .expect("decode connection request row");
        assert_eq!(row.request_id, request_fact.id);
        assert_eq!(row.to_endpoint, request.to_endpoint);
        assert_eq!(
            row.initiator_ephemeral_secret_fact_id,
            request.initiator_ephemeral_secret_fact_id
        );
        // A local outbound request projects its bootstrap route into the row.
        assert_eq!(row.bootstrap_addr, request.to_listen_addr);
        assert!(row.bootstrap_addr.is_some());
    }

    #[test]
    fn local_request_without_route_projects_no_bootstrap_addr() {
        let (mut request, _, invite_fact, ephemeral_fact) = signed_request_fact(FactScope::Local);
        let invite = invite_layout::decode_fact(invite_fact.body()).expect("decode invite");
        request.to_listen_addr = None;
        request.invite_signature = crypto::ed25519_sign(
            &invite.bootstrap_secret,
            &invite_signing_transcript(&request).expect("transcript"),
        );
        let request_fact = Fact::new(
            FactScope::Local,
            12,
            layout::encode_fact(&request).expect("encode request"),
        );
        let context = ProjectionContext::from_matches(vec![
            invite_match(request_fact.id, invite_fact),
            ephemeral_match(request_fact.id, ephemeral_fact),
        ]);

        let output = project::ConnectionRequestProjector::new()
            .project(&request_fact, &context)
            .expect("project request");

        // No bootstrap route means the row is not a pending bootstrap candidate.
        assert!(output.effects.intents.is_empty());
        assert!(output.effects.local_intents.is_empty());
        assert!(output.time_wakes.is_empty());
        let RowMutation::PutRow(row) = &output.effects.row_mutations[0] else {
            panic!("expected put row mutation");
        };
        assert_eq!(
            rows::decode_connection_request_row(&row.key, &row.value)
                .expect("decode row")
                .bootstrap_addr,
            None
        );
        assert!(output
            .needs
            .iter()
            .any(|need| need.role == "connection_response_for_request"));
    }

    #[test]
    fn local_request_with_response_drops_need_without_extra_intents() {
        let (_, request_fact, invite_fact, ephemeral_fact) = signed_request_fact(FactScope::Local);
        let context = ProjectionContext::from_matches(vec![
            invite_match(request_fact.id, invite_fact),
            ephemeral_match(request_fact.id, ephemeral_fact),
            response_match(request_fact.id, request_fact.id),
        ]);

        let output = project::ConnectionRequestProjector::new()
            .project(&request_fact, &context)
            .expect("project request");

        // Answered: drop the standing need, no time wake, no intents. The request
        // row is no longer a pending bootstrap because a connection response row
        // now exists for it (the maintenance query filters it out).
        assert!(output.effects.local_intents.is_empty());
        assert!(output.effects.intents.is_empty());
        assert!(output.time_wakes.is_empty());
        assert!(output.needs.is_empty());
        assert_eq!(output.effects.row_mutations.len(), 1);
    }

    #[test]
    fn received_request_materializes_after_invite_and_receipt_context_match() {
        let (request, request_fact, invite_fact, _) = signed_request_fact(FactScope::Global);
        let context = ProjectionContext::from_matches(vec![
            invite_match(request_fact.id, invite_fact),
            endpoint_match(request_fact.id, request.to_endpoint),
            receive_match(request_fact.id, &request, request_fact.id, 1_700_000_000),
        ]);

        let output = project::ConnectionRequestProjector::new()
            .project(&request_fact, &context)
            .expect("project received request");

        assert_eq!(output.effects.intents.len(), 1);
        assert!(output.effects.local_intents.is_empty());
        assert!(output.time_wakes.is_empty());
        assert_eq!(output.effects.row_mutations.len(), 1);
        assert_eq!(output.offers[0].role.as_str(), "connection_request");
        let response_intent = output
            .effects
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
    fn received_request_is_not_a_bootstrap_candidate_and_only_creates_response() {
        let (request, request_fact, invite_fact, _) = signed_request_fact(FactScope::Global);
        let context = ProjectionContext::from_matches(vec![
            invite_match(request_fact.id, invite_fact),
            endpoint_match(request_fact.id, request.to_endpoint),
            receive_match(request_fact.id, &request, request_fact.id, 1_700_000_000),
        ]);

        let output = project::ConnectionRequestProjector::new()
            .project(&request_fact, &context)
            .expect("project received request");

        // A received request answers a peer; it never schedules a time wake, and
        // its row carries no bootstrap route so it is not a pending bootstrap.
        assert!(output.effects.local_intents.is_empty());
        assert!(output.time_wakes.is_empty());
        let RowMutation::PutRow(row) = &output.effects.row_mutations[0] else {
            panic!("expected put row mutation");
        };
        assert_eq!(
            rows::decode_connection_request_row(&row.key, &row.value)
                .expect("decode row")
                .bootstrap_addr,
            None
        );
        assert_eq!(
            output
                .effects
                .intents
                .iter()
                .filter(|intent| intent.kind.as_str() == CREATE_CONNECTION_RESPONSE)
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

        let output = project::ConnectionRequestProjector::new()
            .project(&request_fact, &context)
            .expect("project received request");

        let response_intents = output
            .effects
            .intents
            .iter()
            .filter(|intent| intent.kind.as_str() == CREATE_CONNECTION_RESPONSE)
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
