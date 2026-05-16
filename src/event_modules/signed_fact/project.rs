//! Projector for local signing capability facts.
//!
//! This projector exposes capability presence, not signing authority policy.
//! It accepts only local secret facts, then offers the signer under the target
//! workspace so commands can be woken when identity has already provisioned the
//! key. Remote signed envelopes should validate signatures elsewhere and must
//! not create local signer-secret offers here.

use crate::core::facts::{Fact, FactScope, ScopeKind};
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
    require_local_scope(fact)?;
    let scope = workspace_scope(secret.workspace_id);
    Ok(
        ProjectionOutput::new().offer(context::local_signer_secret_offer(
            fact.id,
            scope,
            secret.signer_id,
        )),
    )
}

fn workspace_scope(workspace_id: crate::core::facts::FactId) -> FactScope {
    FactScope::Scoped {
        kind: ScopeKind::new("workspace").expect("valid workspace scope"),
        id: workspace_id,
    }
}

fn require_local_scope(fact: &Fact) -> Result<(), String> {
    if fact.scope == FactScope::Local {
        Ok(())
    } else {
        Err("local signer secret fact must have local scope".to_string())
    }
}
