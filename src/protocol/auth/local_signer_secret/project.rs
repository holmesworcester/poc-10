//! Local signer-secret projector.
//!
//! POLICY. A local_signer_secret is admitted iff:
//!   1. STRUCTURAL. The fact is local and decodes as validated private signing
//!      material.
//!   2. CONTEXT. It needs no remote context; local possession is the proof.
//!   3. MATERIALIZE. It publishes local signer context under the workspace
//!      scope and emits no rows, facts, intents, or shareable context.

use crate::core::facts::{Fact, FactScope, ScopeKind};
use crate::core::pipeline::{
    project_staged, FactPipeline, ProjectionContext, ProjectionOutput, Projector, SemanticProjector,
};

use super::fact::LocalSignerSecretFact;

/// Staged read pipeline for the local_signer_secret fact.
pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "auth::local_signer_secret::Codec",
    authenticate: "auth::local_signer_secret::authenticate::LocalSignerSecretAuthenticator",
    adapt: "auth::local_signer_secret::adapt::LocalSignerSecretAdapter",
    project: "auth::local_signer_secret::project::LocalSignerSecretProjector",
};

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
        project_staged::<
            super::Codec,
            super::authenticate::LocalSignerSecretAuthenticator,
            super::adapt::LocalSignerSecretAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<LocalSignerSecretFact> for LocalSignerSecretProjector {
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
