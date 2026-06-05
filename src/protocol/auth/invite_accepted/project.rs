//! Poc-10 invite-accepted projector.
//!
//! POLICY. An invite_accepted fact is admitted iff:
//!   1. STRUCTURAL. The fact is local-only and all fact id/hash fields are
//!      non-zero.
//!   2. CONTEXT. Matched invite_secret context must be local and scoped to the
//!      same workspace/invite/bootstrap hash.
//!   3. MATERIALIZE. Write the invite_accepted row; broader network effects
//!      remain explicit intent-handler work.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::pipeline::{
    project_staged, FactPipeline, ProjectionContext, ProjectionOutput, Projector, SemanticProjector,
};
use crate::protocol::auth::invite;

use super::invite_accepted_row;

/// Staged read pipeline for the invite_accepted fact.
pub const PIPELINE: FactPipeline = FactPipeline::Staged {
    decode: "auth::invite_accepted::Codec",
    authenticate: "auth::invite_accepted::authenticate::InviteAcceptedAuthenticator",
    adapt: "auth::invite_accepted::adapt::InviteAcceptedAdapter",
    project: "auth::invite_accepted::project::InviteAcceptedProjector",
};

#[derive(Debug, Clone, Default)]
pub struct InviteAcceptedProjector;

impl InviteAcceptedProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for InviteAcceptedProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_staged::<
            super::Codec,
            super::authenticate::InviteAcceptedAuthenticator,
            super::adapt::InviteAcceptedAdapter,
            _,
        >(self, fact, context)
    }
}

impl SemanticProjector<super::fact::InviteAcceptedFact> for InviteAcceptedProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        accepted: super::fact::InviteAcceptedFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("invite_accepted fact must have local scope".to_string());
        }

        // 2. Context.
        let secret_need = crate::core::context::ContextNeed::range(
            fact.id,
            "auth_invite_secret",
            crate::core::facts::FactScope::Global,
            accepted.invite_secret_fact_id,
            accepted.invite_secret_fact_id,
        );
        let Some(secret_fact) = context.payload_for(&secret_need) else {
            return Ok(ProjectionOutput::new().need(secret_need));
        };
        if secret_fact.id != accepted.invite_secret_fact_id {
            return Err("invite_accepted invite_secret context payload id mismatch".to_string());
        }
        if secret_fact.scope != FactScope::Local {
            return Err("invite_accepted invite_secret context must be local".to_string());
        }
        let secret = invite::decode_fact_payload(secret_fact.body())
            .map_err(|_| "invite_accepted dependency is not an invite_secret fact".to_string())?;
        if secret.bootstrap_hash != accepted.bootstrap_hash {
            return Err("invite_accepted bootstrap hash does not match invite_secret".to_string());
        }
        if secret.workspace_id != Some(accepted.workspace_id)
            || secret.invite_fact_id != Some(accepted.invite_fact_id)
        {
            return Err(
                "invite_accepted invite_secret scope does not match acceptance".to_string(),
            );
        }
        // 3. Materialize.
        Ok(ProjectionOutput::new()
            .need(secret_need)
            .row_mutation(RowMutation::PutRow(invite_accepted_row(
                fact.id, &accepted,
            )?)))
    }
}
