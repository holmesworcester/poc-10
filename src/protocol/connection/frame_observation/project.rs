//! Connection-frame observation projector.
//!
//! POLICY. A `connection_frame_observation` fact is admitted iff:
//!   1. STRUCTURAL. The fact is local-only and its payload names one frame fact
//!      plus canonical receive metadata.
//!   2. CONTEXT. No external authority is loaded; the matching frame projector
//!      validates and opens the frame bytes.
//!   3. MATERIALIZE. Publish local `connection_frame_observation` context keyed
//!      by the observed frame fact id.

use crate::core::context::ContextOffer;
use crate::core::effects::PipelineEffects;
use crate::core::facts::{Fact, FactScope};
use crate::core::pipeline::{
    project_staged, FactPipeline, ProjectionContext, ProjectionOutput, Projector, SemanticProjector,
};
use crate::protocol::connection::create_frame_observation::{
    create_frame_observation_intent, CreateFrameObservation,
};

use super::fact::ConnectionFrameObservationFact;

pub fn observed_frame_effect(
    frame_fact: Fact,
    origin_addr: &[u8],
    received_at_local_ms: u64,
    ephemeral: bool,
) -> Result<PipelineEffects, String> {
    let output =
        PipelineEffects::new().intent(create_frame_observation_intent(CreateFrameObservation {
            frame_fact_id: frame_fact.id,
            origin_addr: origin_addr.to_vec(),
            received_at_local_ms,
        }));
    Ok(if ephemeral {
        output.ephemeral_fact(frame_fact)
    } else {
        output.fact(frame_fact)
    })
}

/// Staged read pipeline for the frame_observation fact.
pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "connection::frame_observation::Codec",
    authenticate:
        "connection::frame_observation::authenticate::ConnectionFrameObservationAuthenticator",
    adapt: "connection::frame_observation::adapt::ConnectionFrameObservationAdapter",
    project: "connection::frame_observation::project::ConnectionFrameObservationProjector",
};

#[derive(Debug, Clone, Default)]
pub struct ConnectionFrameObservationProjector;

impl ConnectionFrameObservationProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionFrameObservationProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_staged::<
            super::Codec,
            super::authenticate::ConnectionFrameObservationAuthenticator,
            super::adapt::ConnectionFrameObservationAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<ConnectionFrameObservationFact> for ConnectionFrameObservationProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        observed: ConnectionFrameObservationFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Local {
            return Err("connection frame observation must have local scope".to_string());
        }

        // 2. Context.
        // 3. Materialize.
        Ok(ProjectionOutput::new().offer(ContextOffer::range(
            fact.id,
            "connection_frame_observation",
            FactScope::Local,
            observed.frame_fact_id,
            observed.frame_fact_id,
        )))
    }
}
