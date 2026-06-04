//! Poc-10 user projector.
//!
//! POLICY. A user fact is admitted iff:
//!   1. STRUCTURAL. The outer fact is global, signed, contains a user payload,
//!      and the workspace/public key/name fields are non-empty.
//!   2. AUTHORITY. Matched user_invite context must match the signer id,
//!      signer public key, and workspace.
//!   3. MATERIALIZE. Write the user row, publish user context, and share the
//!      fact with the workspace.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::pipeline::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
};
use crate::protocol::auth::user_invite;
use crate::protocol::sync::shared_fact::project::{context_have_from_needs, share_fact_with_sync};

use super::rows::user_row;

#[derive(Debug, Clone, Default)]
pub struct UserProjector;

impl UserProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for UserProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_authenticated::<super::authenticate::UserAuthenticator, _>(self, fact, context)
    }
}

impl AuthenticatedProjector<super::authenticate::UserAuthenticator> for UserProjector {
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, super::fact::UserFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let (fact, user) = authenticated.into_parts();
        // 1. Structural.
        if fact.scope != FactScope::Global {
            return Err("user fact must have global scope".to_string());
        }

        // 2. Authority.
        let invite_need = crate::core::context::ContextNeed::range(
            fact.id,
            "auth_user_invite",
            crate::core::facts::FactScope::Global,
            user.signer_id,
            user.signer_id,
        );
        let Some(invite_fact) = context.payload_for(&invite_need) else {
            return Ok(ProjectionOutput::new().need(invite_need));
        };
        if invite_fact.id != user.signer_id {
            return Err("user signer context payload id mismatch".to_string());
        }
        let invite = user_invite::decode_fact_payload(invite_fact.body())
            .map_err(|_| "user signer context must be a user_invite fact".to_string())?;
        if invite.workspace_id != user.workspace_id {
            return Err("user workspace does not match user_invite workspace".to_string());
        }
        if invite.public_key != user.signer_public_key {
            return Err("signed user signer key does not match user_invite public key".to_string());
        }
        let user_invite_id = invite_fact.id;
        let context_have = context_have_from_needs(context, [&invite_need]);

        // 3. Materialize.
        Ok(share_fact_with_sync(
            ProjectionOutput::new()
                .need(invite_need)
                .offer(crate::core::context::ContextOffer::range(
                    fact.id,
                    "auth_user",
                    crate::core::facts::FactScope::Global,
                    fact.id,
                    fact.id,
                ))
                .row_mutation(RowMutation::PutRow(user_row(
                    fact.id,
                    user_invite_id,
                    &user,
                )?)),
            user.workspace_id,
            fact,
            context_have,
        ))
    }
}
