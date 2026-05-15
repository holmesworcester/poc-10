//! Projector for local signing capability facts.

use crate::core::facts::Fact;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::{context, layout};

#[derive(Debug, Clone, Default)]
pub struct SignedFactProjector;

impl SignedFactProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for SignedFactProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        match fact.bytes.first().copied() {
            Some(layout::TYPE_LOCAL_SIGNER_SECRET) => project_local_signer_secret(fact),
            _ => Err("unknown signed-fact helper type".to_string()),
        }
    }
}

fn project_local_signer_secret(fact: &Fact) -> Result<ProjectionOutput, String> {
    let secret = layout::decode_local_signer_secret(&fact.bytes)?;
    Ok(
        ProjectionOutput::new().offer(context::local_signer_secret_offer(
            fact.id,
            fact.scope.clone(),
            secret.signer_id,
        )),
    )
}
