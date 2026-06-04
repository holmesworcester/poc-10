//! Membership connection-request projector.
//!
//! Request projection validates a durable membership handshake request. Both
//! The receiver first proves the initiator's `endpoint_shared` membership (context
//! role `auth_endpoint_shared`) and verify the request endpoint signature
//! against that membership signing key. Received requests additionally prove
//! that the local endpoint is a member of the same workspace (role
//! `content_signer`, mutual membership) plus the socket observation, then emit a
//! receipt fact, a `connection_request_received` fact, and deferred response
//! creation.
//!
//! POLICY. A connection_request is admitted iff:
//!   1. STRUCTURAL. The fact is local or global, fields are non-empty, endpoints
//!      differ.
//!   2. MEMBERSHIP. The initiator `endpoint_shared` is held, binds the sender
//!      endpoint, and its signing key verifies the endpoint signature.
//!   3. CONTEXT. Received requests prove local endpoint ownership, mutual
//!      workspace membership (PARK if not yet synced), and a frame observation.
//!   4. MATERIALIZE. Offer request context, emit receive history, emit deferred
//!      response creation, and learn the initiator's reachable address.
//!
//! There is no invite material on this path. Change this projector for
//! membership admission and branch context; byte layout lives in `layout.rs`,
//! the signing transcript in `create.rs`, and response construction in
//! `create_connection_response.rs` plus `connection_response::create`.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::projectors::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, FactCodec, ProjectionContext,
    ProjectionOutput, Projector,
};

use crate::protocol::auth::{endpoint, endpoint_shared, workspace};
use crate::protocol::connection::connection_request_received;
use crate::protocol::connection::connection_request_received::fact::ConnectionRequestReceivedFact;
use crate::protocol::connection::create_connection_response::{
    create_connection_response_intent, CreateConnectionResponse,
};
use crate::protocol::connection::frame_observation;
use crate::protocol::connection::observed_endpoint_address::rows::observed_endpoint_address_row;
use crate::protocol::connection_frame::{
    connection_fact_receipt_for_path, ConnectionFactReceiptInput,
};

use super::fact::ConnectionRequestFact;

const MEMBERSHIP_CONNECTION_REQUEST_ROLE: &str = "membership_connection_request";
const MEMBERSHIP_CONNECTION_RESPONSE_FOR_REQUEST_ROLE: &str =
    "membership_connection_response_for_request";

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
        project_authenticated::<super::authenticate::ConnectionRequestAuthenticator, _>(
            self,
            fact,
            projection_context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::ConnectionRequestAuthenticator>
    for ConnectionRequestProjector
{
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, ConnectionRequestFact>,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // Authentication (see authenticate.rs) proved canonical bytes, the
        // non-empty selectors, and the endpoint signature against the initiator's
        // membership key. Scope and membership are interpretation.
        let (fact, request) = authenticated.into_parts();
        // 1. Scope.
        if !matches!(fact.scope, FactScope::Local | FactScope::Global) {
            return Err("membership connection request fact must be local or global".to_string());
        }

        // 2. Membership proof (both branches): the initiator's endpoint_shared
        // binds its endpoint to this workspace. The endpoint signature itself was
        // verified during authentication.
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
                "membership connection request endpoint_shared does not bind the sender"
                    .to_string(),
            );
        }
        let workspace_id = initiator_shared.workspace_id;

        if fact.scope != FactScope::Global {
            return Err("membership connection request fact must be received/global".to_string());
        }

        // 3. Received membership request path.
        let endpoint_need = crate::core::context::ContextNeed::range(
            fact.id,
            "auth_local_endpoint",
            FactScope::Local,
            request.to_endpoint,
            request.to_endpoint,
        );
        let membership_need = content_signer_need(fact.id, workspace_id, request.to_endpoint);
        let observation_need = crate::core::context::ContextNeed::range(
            fact.id,
            "connection_frame_observation",
            FactScope::Local,
            fact.id,
            fact.id,
        );
        let Some(endpoint_context) = projection_context.payload_for(&endpoint_need) else {
            return Ok(waiting_output([
                shared_need,
                endpoint_need,
                membership_need,
                observation_need,
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
                observation_need,
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
        let Some(observation_fact) = projection_context.payload_for(&observation_need) else {
            return Ok(waiting_output([
                shared_need,
                endpoint_need,
                membership_need,
                observation_need,
            ]));
        };
        if observation_fact.scope != FactScope::Local {
            return Err(
                "membership connection request observation context must be local".to_string(),
            );
        }
        let observation =
            frame_observation::Codec::decode_fact(observation_fact).map_err(|_| {
                "membership connection request observation context is malformed".to_string()
            })?;
        if observation.frame_fact_id != fact.id {
            return Err(
                "membership connection request observation targets another fact".to_string(),
            );
        }
        if request.from_listen_addr.is_none() {
            return Err("membership connection request response route is missing".to_string());
        }

        // 4. Materialize received request and schedule response creation.
        received_materialized_output(
            fact.id,
            &request,
            observation.origin_addr.bytes(),
            crate::core::crypto::hash(fact.body()),
            observation.received_at_local_ms,
        )
    }
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

fn received_materialized_output(
    request_id: [u8; 32],
    request: &ConnectionRequestFact,
    origin_addr: &[u8],
    frame_hash: [u8; 32],
    received_at_local_ms: u64,
) -> Result<ProjectionOutput, String> {
    let receipt = connection_fact_receipt_for_path(ConnectionFactReceiptInput {
        received_fact_id: request_id,
        origin_addr,
        local_endpoint_id: request.to_endpoint,
        sender_endpoint_id: request.from_endpoint,
        receive_path:
            crate::protocol::connection::fact_receipt::fact::RECEIVE_PATH_CONNECTION_REQUEST,
        connection_id: None,
        request_id: Some(request_id),
        frame_hash,
        received_at_local_ms,
    })?;
    let received = crate::core::facts::Fact::new(
        FactScope::Local,
        received_at_local_ms,
        connection_request_received::layout::encode_fact(&ConnectionRequestReceivedFact {
            request_id,
            receive_id: receipt.id,
            received_at_local_ms,
        })?,
    );
    let mut output = materialized_output(request_id)
        .fact(receipt.clone())
        .fact(received)
        .intent(create_connection_response_intent(
            CreateConnectionResponse {
                request_id,
                initiator_endpoint_shared_id: request.initiator_endpoint_shared_id,
                receive_id: receipt.id,
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
