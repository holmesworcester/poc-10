//! Poc-10 transient transport::transit input projector.
//!
//! POLICY. A transit input is admitted iff:
//!   1. STRUCTURAL. The fact is a local ephemeral projection input whose frame
//!      is one supported transit shape: bootstrap request, bootstrap response,
//!      or encrypted connection frame.
//!   2. CONTEXT. Bootstrap requests need invite-secret and local-endpoint
//!      context; encrypted connection frames need local connection-response
//!      context. Missing context is a one-shot need, so core drops unopenable
//!      transit inputs after the first needs check.
//!   3. MATERIALIZE. Opened frames emit durable child facts plus
//!      transport::transit_received provenance. Child facts project immediately
//!      or park on durable context in the same projection transaction.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactScope};
use crate::core::projectors::{
    project_typed, FactCodec, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::{connection, identity};

use super::create::{
    self, BootstrapFrameKind, OpenBootstrapRequest, OpenBootstrapResponse, OpenReceivedFrame,
};
use super::fact::TransitInputFact;

#[derive(Debug, Clone, Default)]
pub struct TransitProjector;

impl TransitProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for TransitProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for TransitProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        input: TransitInputFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Local {
            return Err("transport::transit input must have local scope".to_string());
        }

        // 2. Context.
        match create::bootstrap_frame_kind(&input.frame) {
            Err(_) => Ok(ProjectionOutput::new()),
            Ok(kind) => match kind {
                BootstrapFrameKind::ConnectionRequest(request) => {
                    project_bootstrap_request(fact, input, request, context)
                }
                BootstrapFrameKind::ConnectionResponse(_) => project_bootstrap_response(input),
                BootstrapFrameKind::ConnectionFrame => {
                    project_connection_frame(fact, input, context)
                }
            },
        }
    }
}

fn project_bootstrap_request(
    owner: &Fact,
    input: TransitInputFact,
    request: connection::request::fact::ConnectionRequestFact,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let invite_need = exact_need(
        owner.id,
        "connection_invite_secret",
        FactScope::Local,
        request.invite_secret_fact_id,
    );
    let endpoint_need = exact_need(
        owner.id,
        "identity_local_endpoint",
        FactScope::Local,
        request.to_endpoint,
    );

    let Some(invite_fact) = context.payload_for(&invite_need) else {
        return Ok(waiting_output([invite_need, endpoint_need]));
    };
    let Some(endpoint_fact) = context.payload_for(&endpoint_need) else {
        return Ok(waiting_output([invite_need, endpoint_need]));
    };
    if invite_fact.id != request.invite_secret_fact_id {
        return Err("transport::transit invite context id does not match request".to_string());
    }
    if invite_fact.scope != FactScope::Local {
        return Err("transport::transit invite context must be local".to_string());
    }
    if endpoint_fact.scope != FactScope::Local {
        return Err("transport::transit endpoint context must be local".to_string());
    }
    let local_endpoint = identity::endpoint::Codec::decode_fact(endpoint_fact)
        .map_err(|_| "transport::transit endpoint context is not a local endpoint".to_string())?;
    if local_endpoint.endpoint != request.to_endpoint {
        return Err("transport::transit endpoint context does not match request".to_string());
    }

    // 3. Materialize.
    let opened = match create::open_bootstrap_request(OpenBootstrapRequest {
        frame: &input.frame,
        invite_fact,
        local_endpoint: &local_endpoint,
        origin_addr: &input.origin_addr,
        received_at_local_ms: input.received_at_local_ms,
    }) {
        Ok(opened) => opened,
        Err(_) => return Ok(ProjectionOutput::new()),
    };
    Ok(facts_output(opened.facts))
}

fn project_bootstrap_response(input: TransitInputFact) -> Result<ProjectionOutput, String> {
    // 3. Materialize.
    match create::open_bootstrap_response(OpenBootstrapResponse {
        frame: &input.frame,
        origin_addr: &input.origin_addr,
        received_at_local_ms: input.received_at_local_ms,
    }) {
        Ok(facts) => Ok(facts_output(facts)),
        Err(_) => Ok(ProjectionOutput::new()),
    }
}

fn project_connection_frame(
    owner: &Fact,
    input: TransitInputFact,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let Ok(connection_id) = super::frame::received_connection_fact_id(&input.frame) else {
        return Ok(ProjectionOutput::new());
    };
    let connection_need = exact_need(
        owner.id,
        "connection_response",
        FactScope::Local,
        connection_id,
    );
    let Some(connection_fact) = context.payload_for(&connection_need) else {
        return Ok(waiting_output([connection_need]));
    };
    if connection_fact.id != connection_id {
        return Err("transport::transit connection context id does not match frame".to_string());
    }
    if connection_fact.scope != FactScope::Local {
        return Err("transport::transit connection context must be local".to_string());
    }

    // 3. Materialize.
    match create::open_received_frame(OpenReceivedFrame {
        frame: &input.frame,
        connection_fact,
        origin_addr: &input.origin_addr,
        received_at_local_ms: input.received_at_local_ms,
    }) {
        Ok(facts) => Ok(facts_output(facts)),
        Err(_) => Ok(ProjectionOutput::new()),
    }
}

fn exact_need(owner: [u8; 32], role: &'static str, scope: FactScope, key: [u8; 32]) -> ContextNeed {
    ContextNeed::range(owner, role, scope, key, key)
}

fn waiting_output<const N: usize>(needs: [ContextNeed; N]) -> ProjectionOutput {
    let mut output = ProjectionOutput::new();
    for need in needs {
        output = output.need(need);
    }
    output
}

fn facts_output(facts: Vec<Fact>) -> ProjectionOutput {
    let mut output = ProjectionOutput::new();
    for fact in facts {
        output = output.fact(fact);
    }
    output
}
