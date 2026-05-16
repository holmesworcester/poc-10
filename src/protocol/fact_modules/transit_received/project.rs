//! Poc-10 transit receive provenance projector.

use crate::core::facts::{Fact, FactScope};
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::protocol::matchers;

use super::layout;

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
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if fact.scope != FactScope::Local {
            return Err("transit received fact must have FactScope::Local".to_string());
        }
        let received = layout::decode_fact(&fact.bytes)?;
        Ok(
            ProjectionOutput::new().offer(matchers::transit_received_offer(
                fact.id,
                received.received_fact_id,
            )),
        )
    }
}
