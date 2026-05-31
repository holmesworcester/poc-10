//! Membership connection-request projector.
//!
//! Request projection validates a durable membership handshake request. Both
//! branches first prove the initiator's `endpoint_shared` membership (context
//! role `auth_endpoint_shared`) and verify the request endpoint signature
//! against that membership signing key. Local requests then prove initiator
//! ephemeral context and emit the network-send intent for the sealed request
//! bytes. Received requests additionally prove that the local endpoint is a
//! member of the same workspace (role `content_signer`, mutual membership) plus
//! a fact receipt, then emit deferred response creation.
//!
//! POLICY. A connection_request is admitted iff:
//!   1. STRUCTURAL. The fact is local or global, fields are non-empty, endpoints
//!      differ.
//!   2. MEMBERSHIP. The initiator `endpoint_shared` is held, binds the sender
//!      endpoint, and its signing key verifies the endpoint signature.
//!   3. BRANCH CONTEXT. Local requests prove initiator ephemeral secret.
//!      Received requests prove local endpoint ownership, mutual workspace
//!      membership (PARK if not yet synced), and a connection request receipt.
//!   4. MATERIALIZE. Offer request context; local requests schedule peer-retry
//!      sends until a response appears; received requests emit deferred response
//!      creation and learn the initiator's reachable address.
//!
//! There is no invite material on this path. Change this projector for
//! membership admission and branch context; byte layout lives in `layout.rs`,
//! the signing transcript in `create.rs`, and response construction in
//! `create_connection_response.rs` plus `connection_response::create`.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TimeWake, TypedProjector,
};

use crate::protocol::auth::{endpoint, endpoint_shared, workspace};
use crate::protocol::connection::create_connection_response::{
    create_connection_response_intent, CreateConnectionResponse,
};
use crate::protocol::connection::ephemeral_secret;
use crate::protocol::connection::fact_receipt;
use crate::protocol::connection::observed_endpoint_address::rows::observed_endpoint_address_row;
use crate::protocol::connection::send_connection_request::{
    send_connection_request_intent, SendConnectionRequest,
};

use super::create::validate_endpoint_signature;
use super::fact::ConnectionRequestFact;

const PEER_RETRY_IMMEDIATE_AT_MS: u64 = 0;
const PEER_RETRY_DELAY_MS: u64 = 250;

const MEMBERSHIP_CONNECTION_REQUEST_ROLE: &str = "membership_connection_request";
const MEMBERSHIP_CONNECTION_RESPONSE_FOR_REQUEST_ROLE: &str =
    "membership_connection_response_for_request";

/// Peer-retry timeline shared with bootstrap: it is keyed per request fact, so
/// reusing the constant does not cross requests.
pub fn peer_retry_timeline() -> crate::core::projectors::Timeline {
    crate::protocol::connection::bootstrap_request::peer_retry_timeline()
}

pub fn connection_request_need(
    owner: crate::core::facts::FactId,
    request_id: crate::core::facts::FactId,
) -> crate::core::context::ContextNeed {
    crate::core::context::ContextNeed::range(
        owner,
        crate::core::context::Role::expect(MEMBERSHIP_CONNECTION_REQUEST_ROLE),
        crate::core::facts::FactScope::Global,
        request_id,
        request_id,
    )
}

pub fn connection_request_offer(
    owner: crate::core::facts::FactId,
    request_id: crate::core::facts::FactId,
) -> crate::core::context::ContextOffer {
    crate::core::context::ContextOffer::range(
        owner,
        crate::core::context::Role::expect(MEMBERSHIP_CONNECTION_REQUEST_ROLE),
        crate::core::facts::FactScope::Global,
        request_id,
        request_id,
    )
}

pub fn connection_response_for_request_need(
    owner: crate::core::facts::FactId,
    request_id: crate::core::facts::FactId,
) -> crate::core::context::ContextNeed {
    crate::core::context::ContextNeed::range(
        owner,
        crate::core::context::Role::expect(MEMBERSHIP_CONNECTION_RESPONSE_FOR_REQUEST_ROLE),
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
        crate::core::context::Role::expect(MEMBERSHIP_CONNECTION_RESPONSE_FOR_REQUEST_ROLE),
        crate::core::facts::FactScope::Local,
        request_id,
        request_id,
    )
}

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
            return Err("membership connection request fact must be local or global".to_string());
        }
        validate_request_fields(&request)?;
        if request.from_endpoint == request.to_endpoint {
            return Err("membership connection request endpoints must differ".to_string());
        }

        // 2. Membership signature proof (both branches): the initiator's
        // endpoint_shared binds its endpoint and signing key.
        let shared_need = endpoint_shared_need(fact.id, request.initiator_endpoint_shared_id);
        let Some(shared_ctx) = projection_context.payload_for(&shared_need) else {
            return Ok(waiting_output([shared_need]));
        };
        if shared_ctx.id != request.initiator_endpoint_shared_id {
            return Err(
                "membership connection request endpoint_shared context id does not match"
                    .to_string(),
            );
        }
        if shared_ctx.scope != FactScope::Global {
            return Err("membership connection request endpoint_shared must be global".to_string());
        }
        let initiator_shared =
            endpoint_shared::decode_fact_payload(shared_ctx.body()).map_err(|_| {
                "membership connection request endpoint_shared context is malformed".to_string()
            })?;
        if initiator_shared.endpoint_id != request.from_endpoint {
            return Err(
                "membership connection request endpoint_shared does not bind the sender".to_string(),
            );
        }
        validate_endpoint_signature(&request, &initiator_shared.signing_public_key)?;
        let workspace_id = initiator_shared.workspace_id;

        if fact.scope == FactScope::Local {
            // 3a. Local send path: prove initiator ephemeral material.
            let ephemeral_need = crate::core::context::ContextNeed::range(
                fact.id,
                "connection_ephemeral_secret",
                FactScope::Local,
                request.initiator_ephemeral_secret_fact_id,
                request.initiator_ephemeral_secret_fact_id,
            );
            let Some(ephemeral) = projection_context.payload_for(&ephemeral_need) else {
                return Ok(waiting_output([shared_need, ephemeral_need]));
            };
            let ephemeral_secret =
                ephemeral_secret::decode_fact_payload(&ephemeral.bytes).map_err(|_| {
                    "membership connection request dependency is not an ephemeral secret"
                        .to_string()
                })?;
            if ephemeral.id != request.initiator_ephemeral_secret_fact_id {
                return Err(
                    "membership connection request ephemeral context id does not match".to_string(),
                );
            }
            if ephemeral.scope != FactScope::Local {
                return Err(
                    "membership connection request ephemeral context must be local".to_string(),
                );
            }
            if ephemeral_secret.owner_endpoint != request.from_endpoint {
                return Err(
                    "membership connection request ephemeral owner does not match sender"
                        .to_string(),
                );
            }
            if ephemeral_secret.ephemeral_public_key != request.initiator_ephemeral_public_key {
                return Err(
                    "membership connection request ephemeral public key does not match dependency"
                        .to_string(),
                );
            }
            // 4. Materialize local request.
            let response_need = connection_response_for_request_need(fact.id, fact.id);
            if let Some(response_fact) = projection_context.payload_for(&response_need) {
                if response_fact.scope != FactScope::Local {
                    return Err(
                        "membership connection request response context must be local".to_string(),
                    );
                }
                let response = crate::protocol::connection::connection_response::decode_fact_payload(
                    response_fact.body(),
                )
                .map_err(|_| {
                    "membership connection request response context is not a response fact"
                        .to_string()
                })?;
                if response.request_id != fact.id {
                    return Err(
                        "membership connection request response context targets another request"
                            .to_string(),
                    );
                }
                return Ok(materialized_output(fact.id));
            }
            return Ok(local_retrying_output(
                fact,
                &request,
                response_need,
                projection_context,
            )?);
        }

        // 3b. Received membership request path.
        let endpoint_need = crate::core::context::ContextNeed::range(
            fact.id,
            "auth_local_endpoint",
            FactScope::Local,
            request.to_endpoint,
            request.to_endpoint,
        );
        let membership_need = content_signer_need(fact.id, workspace_id, request.to_endpoint);
        let receive_need = crate::core::context::ContextNeed::range(
            fact.id,
            "connection_fact_receipt",
            FactScope::Local,
            fact.id,
            fact.id,
        );
        let Some(endpoint_context) = projection_context.payload_for(&endpoint_need) else {
            return Ok(waiting_output([
                shared_need,
                endpoint_need,
                membership_need,
                receive_need,
            ]));
        };
        if endpoint_context.scope != FactScope::Local {
            return Err("membership connection request endpoint context must be local".to_string());
        }
        let local_endpoint =
            endpoint::decode_fact_payload(endpoint_context.body()).map_err(|_| {
                "membership connection request endpoint context is not a local endpoint".to_string()
            })?;
        if local_endpoint.endpoint != request.to_endpoint {
            return Err(
                "membership connection request endpoint context does not match request".to_string(),
            );
        }
        // Mutual membership: we hold an endpoint_shared placing OUR endpoint in
        // the initiator's workspace. PARK (do not reject) when not yet synced.
        let Some(member_context) = projection_context.payload_for(&membership_need) else {
            return Ok(waiting_output([
                shared_need,
                endpoint_need,
                membership_need,
                receive_need,
            ]));
        };
        let member_shared =
            endpoint_shared::decode_fact_payload(member_context.body()).map_err(|_| {
                "membership connection request mutual-membership context is malformed".to_string()
            })?;
        if member_shared.endpoint_id != request.to_endpoint {
            return Err(
                "membership connection request mutual membership does not bind local endpoint"
                    .to_string(),
            );
        }
        if member_shared.workspace_id != workspace_id {
            return Err(
                "membership connection request mutual membership is in another workspace"
                    .to_string(),
            );
        }
        let Some(receive) = projection_context
            .matched_payloads_for(&receive_need)
            .map(|(_, fact)| fact)
            .min_by_key(|fact| fact.id)
        else {
            return Ok(waiting_output([
                shared_need,
                endpoint_need,
                membership_need,
                receive_need,
            ]));
        };
        if receive.scope != FactScope::Local {
            return Err("membership connection request receive context must be local".to_string());
        }
        let received = fact_receipt::decode_fact_payload(receive.body()).map_err(|_| {
            "membership connection request receive context is not connection fact receipt"
                .to_string()
        })?;
        if received.received_fact_id != fact.id {
            return Err(
                "membership connection request receive context targets another fact".to_string(),
            );
        }
        if received.receive_path != fact_receipt::fact::RECEIVE_PATH_CONNECTION_REQUEST {
            return Err(
                "membership connection request requires connection request receipt".to_string(),
            );
        }
        if received.local_endpoint_id != request.to_endpoint {
            return Err("membership connection request addressed to a different endpoint".to_string());
        }
        if received.sender_endpoint_id != request.from_endpoint {
            return Err(
                "membership connection request sender does not match receive sender".to_string(),
            );
        }
        if let Some(request_id) = received.request_id {
            if request_id != fact.id {
                return Err(
                    "membership connection request fact receipt names another request".to_string(),
                );
            }
        }
        if request.from_listen_addr.is_none() {
            return Err("membership connection request response route is missing".to_string());
        }

        // 4. Materialize received request and schedule response creation.
        received_materialized_output(fact.id, &request, receive.id)
    }
}

fn validate_request_fields(request: &ConnectionRequestFact) -> Result<(), String> {
    if request.from_endpoint == [0; 32] {
        return Err("membership connection request from_endpoint cannot be empty".to_string());
    }
    if request.to_endpoint == [0; 32] {
        return Err("membership connection request to_endpoint cannot be empty".to_string());
    }
    if request.initiator_endpoint_shared_id == [0; 32] {
        return Err(
            "membership connection request initiator_endpoint_shared_id cannot be empty".to_string(),
        );
    }
    if request.initiator_ephemeral_secret_fact_id == [0; 32] {
        return Err(
            "membership connection request initiator_ephemeral_secret_fact_id cannot be empty"
                .to_string(),
        );
    }
    if request.initiator_ephemeral_public_key == [0; 32] {
        return Err(
            "membership connection request initiator_ephemeral_public_key cannot be empty"
                .to_string(),
        );
    }
    Ok(())
}

fn endpoint_shared_need(
    owner: [u8; 32],
    endpoint_shared_id: [u8; 32],
) -> crate::core::context::ContextNeed {
    crate::core::context::ContextNeed::range(
        owner,
        "auth_endpoint_shared",
        FactScope::Global,
        endpoint_shared_id,
        endpoint_shared_id,
    )
}

fn content_signer_need(
    owner: [u8; 32],
    workspace_id: [u8; 32],
    endpoint_id: [u8; 32],
) -> crate::core::context::ContextNeed {
    crate::core::context::ContextNeed::range(
        owner,
        "content_signer",
        workspace::scope(workspace_id),
        endpoint_id,
        endpoint_id,
    )
}

fn materialized_output(request_id: [u8; 32]) -> ProjectionOutput {
    ProjectionOutput::new().offer(connection_request_offer(request_id, request_id))
}

fn local_retrying_output(
    fact: &Fact,
    request: &ConnectionRequestFact,
    response_need: crate::core::context::ContextNeed,
    projection_context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let mut output = materialized_output(fact.id).need(response_need);
    let Some(addr) = request.to_listen_addr else {
        return Ok(output);
    };
    // `PutRow` is insert-or-ignore; a same-output delete-then-put would delete
    // the row (commit applies puts before deletes), so the put stands alone.
    output = output.row_mutation(RowMutation::PutRow(observed_endpoint_address_row(
        request.to_endpoint,
        addr,
    )?));

    let retry_timeline = peer_retry_timeline();
    let due_retry_at = projection_context.time_reached(&retry_timeline, PEER_RETRY_IMMEDIATE_AT_MS);
    if let Some(now_ms) = due_retry_at {
        output = output.local_intent(send_connection_request_intent(SendConnectionRequest {
            request_id: fact.id,
            initiator_ephemeral_secret_id: request.initiator_ephemeral_secret_fact_id,
            addr,
        })?);
        output = output.time_wake(TimeWake {
            owner: fact.id,
            timeline: retry_timeline,
            at: now_ms.saturating_add(PEER_RETRY_DELAY_MS),
        });
    } else {
        output = output.time_wake(TimeWake {
            owner: fact.id,
            timeline: retry_timeline,
            at: PEER_RETRY_IMMEDIATE_AT_MS,
        });
    }
    Ok(output)
}

fn received_materialized_output(
    request_id: [u8; 32],
    request: &ConnectionRequestFact,
    receive_id: [u8; 32],
) -> Result<ProjectionOutput, String> {
    let mut output =
        materialized_output(request_id).intent(create_connection_response_intent(
            CreateConnectionResponse {
                request_id,
                initiator_endpoint_shared_id: request.initiator_endpoint_shared_id,
                receive_id,
            },
        ));
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
