//! Poc-10 local endpoint projector.
//!
//! Decodes the endpoint fact (which re-derives both public keys to detect
//! corruption) and emits four `PutRow` atomic intents under `b"local"`.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::layout;
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
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if fact.scope != FactScope::Local {
            return Err("local endpoint fact must have local scope".to_string());
        }
        let endpoint = layout::decode_fact(&fact.bytes)?;
        let mut output = ProjectionOutput::new();
        for row in endpoint_rows(&endpoint) {
            output = output.intent(AtomicIntent::PutRow(row).into_intent());
        }
        Ok(output)
    }
}
