//! File-slice connection-frame projector.
//!
//! POLICY. A `connection_frame_file_slice` fact is admitted iff:
//!   1. STRUCTURAL. The fact is local ephemeral input and its layout contains
//!      exactly one file-slice encrypted connection frame with receive
//!      metadata.
//!   2. CONTEXT. The frame header names an exact local `connection_response`
//!      context. Missing context emits only a transient need for the fixed-point
//!      pass; malformed and undecryptable frames produce no durable output.
//!   3. MATERIALIZE. Opened inner facts are admitted as durable child facts,
//!      each with a durable `connection::fact_receipt`.

use crate::core::facts::Fact;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use super::create;
use super::fact::ConnectionFrameFileSliceFact;

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
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for ConnectionFrameFileSliceProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        input: ConnectionFrameFileSliceFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        // 2. Context.
        // 3. Materialize.
        create::project_received_frame(fact, input, context)
    }
}
