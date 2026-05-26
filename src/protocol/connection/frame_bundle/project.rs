//! Bundled connection-frame projector.
//!
//! POLICY. A `connection_frame_bundle` fact is admitted iff:
//!   1. STRUCTURAL. The fact is local ephemeral input and its layout contains
//!      exactly one bundled encrypted connection frame with receive metadata.
//!   2. CONTEXT. The frame header names an exact local `connection_response`
//!      context. Missing context emits only a transient need for the fixed-point
//!      pass; malformed and undecryptable frames produce no durable output.
//!   3. MATERIALIZE. Opened inner facts are admitted as durable child facts,
//!      each with a durable `connection::fact_receipt`.

use crate::core::facts::Fact;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::connection::frame::create;

use super::fact::ConnectionFrameBundleFact;

#[derive(Debug, Clone, Default)]
pub struct ConnectionFrameBundleProjector;

impl ConnectionFrameBundleProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionFrameBundleProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for ConnectionFrameBundleProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        input: ConnectionFrameBundleFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        // 2. Context.
        // 3. Materialize.
        create::project_received_frame(
            fact,
            input.origin_addr,
            input.received_at_local_ms,
            input.frame.bytes(),
            context,
        )
    }
}
