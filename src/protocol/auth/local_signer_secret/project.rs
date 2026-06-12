//! Local signer-secret projector.
//!
//! POLICY. A local_signer_secret is admitted iff:
//!   1. STRUCTURAL. The fact is local and decodes as validated private signing
//!      material.
//!   2. CONTEXT. It needs no remote context; local possession is the proof.
//!   3. MATERIALIZE. It publishes local signer context under the workspace
//!      scope and emits no rows, facts, intents, or shareable context.

use crate::core::facts::{Fact, FactScope, ScopeKind};
use crate::core::pipeline::{FactPipeline, ProjectionContext, ProjectionOutput, Projector};

use super::fact::LocalSignerSecretFact;

/// Projector route metadata for the local_signer_secret fact.
pub const PIPELINE: FactPipeline =
    FactPipeline::projector("auth::local_signer_secret::project::LocalSignerSecretProjector");

#[derive(Debug, Clone, Default)]
pub struct LocalSignerSecretProjector;

impl LocalSignerSecretProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for LocalSignerSecretProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let decoded = super::decode::decode_fact(fact.body())?;
        let authenticated = super::authenticate::authenticate(fact, decoded, context)?;
        let semantic = super::adapt::adapt(authenticated)?;
        self.project_semantic(fact, semantic, context)
    }
}

impl LocalSignerSecretProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        secret: LocalSignerSecretFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("local signer secret fact must have local scope".to_string());
        }

        // 2. Context.
        // Local possession is the context proof; no durable remote witness is
        // needed before publishing the local signer offer.

        // 3. Materialize.
        Ok(
            ProjectionOutput::new().offer(crate::core::context::ContextOffer::range(
                fact.id,
                "local_signer_secret",
                workspace_scope(secret.workspace_id),
                secret.signer_id,
                secret.signer_id,
            )),
        )
    }
}

fn workspace_scope(workspace_id: crate::core::facts::FactId) -> FactScope {
    FactScope::Scoped {
        kind: ScopeKind::new("workspace").expect("valid workspace scope"),
        id: workspace_id,
    }
}
