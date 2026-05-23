//! Connection fact-receipt projector.
//!
//! POLICY. A connection_fact_receipt is admitted iff:
//!   1. STRUCTURAL. The fact is local-only and its receipt payload decodes.
//!   2. CONTEXT. No authority context is loaded here; higher-level projectors
//!      validate the receipt against their target fact.
//!   3. MATERIALIZE. Publish a local connection_fact_receipt offer for the
//!      received fact so the owning projector can continue.

use crate::core::facts::{Fact, FactScope};
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

#[derive(Debug, Clone, Default)]
pub struct ConnectionFactReceiptProjector;

impl ConnectionFactReceiptProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionFactReceiptProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for ConnectionFactReceiptProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        received: super::fact::ConnectionFactReceipt,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Local {
            return Err("connection fact receipt must have FactScope::Local".to_string());
        }
        // 3. Materialize.
        Ok(
            ProjectionOutput::new().offer(crate::core::context::ContextOffer::range(
                fact.id,
                "connection_fact_receipt",
                crate::core::facts::FactScope::Local,
                received.received_fact_id,
                received.received_fact_id,
            )),
        )
    }
}
