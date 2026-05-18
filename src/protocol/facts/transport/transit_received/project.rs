//! Poc-10 transport::transit receive provenance projector.
//!
//! POLICY. A transit_received fact is admitted iff:
//!   1. STRUCTURAL. The fact is local-only and its provenance payload decodes.
//!   2. CONTEXT. No authority context is loaded here; higher-level projectors
//!      validate that provenance against their target fact.
//!   3. MATERIALIZE. Publish a local transit_received offer for the received
//!      fact so the owning projector can continue.

use crate::core::facts::{Fact, FactScope};
use crate::core::projection::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::matchers;

#[derive(Debug, Clone, Default)]
pub struct TransitReceivedProjector;

impl TransitReceivedProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for TransitReceivedProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for TransitReceivedProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        received: super::fact::TransitReceivedFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Local {
            return Err("transport::transit received fact must have FactScope::Local".to_string());
        }
        // 3. Materialize.
        Ok(
            ProjectionOutput::new().offer(matchers::transit_received_offer(
                fact.id,
                received.received_fact_id,
            )),
        )
    }
}
