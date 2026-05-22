//! Projector for local signing capability facts.
//!
//! POLICY. A signed-fact helper is admitted iff:
//!   1. DISPATCH. The first byte selects a known helper payload, currently only
//!      local signer-secret.
//!   2. CONTEXT. No remote context is accepted; remote signed envelopes validate
//!      signatures in their owning fact modules.
//!   3. MATERIALIZE. Local signer secrets publish local signer context under
//!      their workspace and do not emit row or network work.

use crate::core::facts::{Fact, FactScope, ScopeKind};
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::context_keys;

use super::fact::LocalSignerSecretFact;

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
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Dispatch.
        match fact.bytes.first().copied() {
            Some(super::layout::TYPE_LOCAL_SIGNER_SECRET) => {
                project_typed::<super::Codec, _>(self, fact, context)
            }
            _ => Err("unknown signed-fact helper type".to_string()),
        }
    }
}

impl TypedProjector<super::Codec> for SignedFactProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        secret: LocalSignerSecretFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_local_signer_secret(fact, secret)
    }
}

fn project_local_signer_secret(
    fact: &Fact,
    secret: LocalSignerSecretFact,
) -> Result<ProjectionOutput, String> {
    // 1. Structural.
    require_local_scope(fact)?;
    let scope = workspace_scope(secret.workspace_id);
    // 3. Materialize.
    Ok(
        ProjectionOutput::new().offer(context_keys::local_signer_secret_offer(
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
