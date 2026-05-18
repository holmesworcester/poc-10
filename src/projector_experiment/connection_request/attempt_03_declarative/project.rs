//! Stub. The agent assigned to this slot replaces this file with a maximally
//! readable rewrite of the connection_request projector. The implementation
//! must pass `crate::projector_experiment::connection_request::shared::run_all_invariants`.

use crate::core::facts::Fact;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

#[derive(Debug, Clone, Default)]
pub struct ConnectionRequestProjector;

impl ConnectionRequestProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for ConnectionRequestProjector {
    fn project(&self, _fact: &Fact, _ctx: &ProjectionContext) -> Result<ProjectionOutput, String> {
        unimplemented!("Replace this stub with a readable projector implementation")
    }
}
