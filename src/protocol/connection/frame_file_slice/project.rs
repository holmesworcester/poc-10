//! File-slice connection-frame projector.
//!
//! POLICY. A `connection_frame_file_slice` fact is admitted iff:
//!   1. STRUCTURAL. The fact is local ephemeral input and its layout contains
//!      exactly one file-slice encrypted connection frame.
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
use super::fact::ConnectionFrameFileSliceFact;

/// Staged read pipeline for the frame_file_slice fact.
pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "connection::frame_file_slice::Codec",
    authenticate:
        "connection::frame_file_slice::authenticate::ConnectionFrameFileSliceAuthenticator",
    adapt: "connection::frame_file_slice::adapt::ConnectionFrameFileSliceAdapter",
    project: "connection::frame_file_slice::project::ConnectionFrameFileSliceProjector",
};

#[derive(Debug, Clone, Default)]
pub struct ConnectionFrameFileSliceProjector;

impl ConnectionFrameFileSliceProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionFrameFileSliceProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_staged::<
            super::Codec,
            super::authenticate::ConnectionFrameFileSliceAuthenticator,
            super::adapt::ConnectionFrameFileSliceAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<ConnectionFrameFileSliceFact> for ConnectionFrameFileSliceProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        input: ConnectionFrameFileSliceFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        // 2. Context.
        // 3. Materialize.
        author::project_observed_frame(fact, input, context)
    }
}
