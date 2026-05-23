//! Poc-10 encrypted connection-frame projector.
//!
//! POLICY. A `connection::frame` fact is admitted iff:
//!   1. STRUCTURAL. The fact is a local ephemeral small or large connection
//!      frame whose body encodes the corresponding fixed outer frame shape.
//!   2. CONTEXT. The public frame header names an exact local
//!      connection_response fact. Missing context parks the ephemeral input only
//!      for its first needs check; malformed or undecryptable frames complete
//!      with no durable output.
//!   3. MATERIALIZE. Opened inner facts are admitted as durable child facts,
//!      each with a durable `connection::fact_receipt`. The child
//!      facts project immediately or park on their own durable context in the
//!      same projection transaction.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactScope};
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use super::create::{self, OpenReceivedFrame};
use super::ProjectionPayload;

#[derive(Debug, Clone, Default)]
pub struct ConnectionFrameProjector;

impl ConnectionFrameProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionFrameProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for ConnectionFrameProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        input: ProjectionPayload,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Local {
            return Err("connection::frame fact must have local scope".to_string());
        }

        let (origin_addr, received_at_local_ms, frame) = match input {
            ProjectionPayload::Small(input) => {
                (input.origin_addr, input.received_at_local_ms, input.frame)
            }
            ProjectionPayload::Large(input) => {
                (input.origin_addr, input.received_at_local_ms, input.frame)
            }
        };

        // 2. Context.
        let Ok(connection_id) = super::frame::received_connection_fact_id(&frame) else {
            return Ok(ProjectionOutput::new());
        };
        let connection_need = exact_need(
            fact.id,
            "connection_response",
            FactScope::Local,
            connection_id,
        );
        let Some(connection_fact) = context.payload_for(&connection_need) else {
            return Ok(waiting_output([connection_need]));
        };
        if connection_fact.id != connection_id {
            return Err("connection::frame connection context id does not match frame".to_string());
        }
        if connection_fact.scope != FactScope::Local {
            return Err("connection::frame connection context must be local".to_string());
        }

        // 3. Materialize.
        match create::open_received_frame(OpenReceivedFrame {
            frame: &frame,
            connection_fact,
            origin_addr: &origin_addr,
            received_at_local_ms,
        }) {
            Ok(facts) => Ok(facts_output(facts)),
            Err(_) => Ok(ProjectionOutput::new()),
        }
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
