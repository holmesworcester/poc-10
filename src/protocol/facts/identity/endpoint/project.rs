//! Poc-10 local endpoint projector.
//!
//! POLICY. A local endpoint fact is admitted iff:
//!   1. STRUCTURAL. The fact is local-only and endpoint layout re-derives both
//!      public keys from the stored private keys.
//!   2. CONTEXT. No remote context is accepted; this is local identity secret
//!      material.
//!   3. MATERIALIZE. Write the four local endpoint rows for public/secret and
//!      signing public/secret material.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};

use super::rows::endpoint_rows;

#[derive(Debug, Clone, Default)]
pub struct EndpointProjector;

impl EndpointProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for EndpointProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for EndpointProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        endpoint: super::fact::EndpointFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Local {
            return Err("local endpoint fact must have local scope".to_string());
        }

        // 3. Materialize.
        let mut output = ProjectionOutput::new();
        for row in endpoint_rows(&endpoint) {
            output = output.row_mutation(RowMutation::PutRow(row));
        }
        Ok(output)
    }
}
