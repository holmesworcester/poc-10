//! Small connection-frame projector.
//!
//! POLICY. A `connection_frame_small` fact is admitted iff:
//!   1. STRUCTURAL. The fact is local ephemeral input and its layout contains
//!      exactly one small encrypted connection frame.
//!   2. CONTEXT. The frame fact has exact local `connection_frame_observation`
//!      context, and its header names an exact local `connection`
//!      context. Missing context emits only a transient need for the fixed-point
//!      pass; malformed and undecryptable frames produce no durable output.
//!   3. MATERIALIZE. Opened inner facts are admitted as durable child facts,
//!      each with a durable `connection::fact_receipt`.

use crate::core::facts::Fact;
use crate::core::pipeline::{
    project_staged, FactPipeline, ProjectionContext, ProjectionOutput, Projector, SemanticProjector,
};

use super::author;
use super::fact::ConnectionFrameSmallFact;

/// Staged read pipeline for the frame_small fact.
pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "connection::frame_small::Codec",
    authenticate: "connection::frame_small::authenticate::ConnectionFrameSmallAuthenticator",
    adapt: "connection::frame_small::adapt::ConnectionFrameSmallAdapter",
    project: "connection::frame_small::project::ConnectionFrameSmallProjector",
};

#[derive(Debug, Clone, Default)]
pub struct ConnectionFrameSmallProjector;

impl ConnectionFrameSmallProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionFrameSmallProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_staged::<
            super::Codec,
            super::authenticate::ConnectionFrameSmallAuthenticator,
            super::adapt::ConnectionFrameSmallAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<ConnectionFrameSmallFact> for ConnectionFrameSmallProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        input: ConnectionFrameSmallFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        // 2. Context.
        // 3. Materialize.
        author::project_observed_frame(fact, input, context)
    }
}
