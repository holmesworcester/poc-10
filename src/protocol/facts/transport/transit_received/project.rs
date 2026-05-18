//! Poc-10 transport::transit receive provenance projector.

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
            return Err("transport::transit received fact must have FactScope::Local".to_string());
        }
        let received = layout::decode_fact(fact.body())?;
        Ok(
            ProjectionOutput::new().offer(matchers::transit_received_offer(
                fact.id,
                received.received_fact_id,
            )),
        )
    }
}
