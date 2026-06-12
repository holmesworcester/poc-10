//! Poc-10 user projector.
//!
//! POLICY. A user fact is admitted iff:
//!   1. STRUCTURAL. The outer fact is global, carries signer identity, contains a user payload,
//!      and the workspace/public key/name fields are non-empty.
//!   2. AUTHORITY. Matched user_invite context must match the signer id,
//!      signer public key, and workspace.
//!   3. MATERIALIZE. Write the user row, publish user context, and share the
//!      fact with the workspace.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::pipeline::{FactPipeline, ProjectionContext, ProjectionOutput, Projector};
use crate::protocol::auth::{signature, user_invite};
use crate::protocol::sync::shared_fact::project::{context_have_from_needs, share_fact_with_sync};

use super::user_row;

/// Projector route metadata for the user fact.
pub const PIPELINE: FactPipeline = FactPipeline::projector("auth::user::project::UserProjector");

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
        let decoded = super::decode::decode_fact(fact.body())?;
        let authenticated = super::authenticate::authenticate(fact, decoded, context)?;
        let semantic = super::adapt::adapt(authenticated)?;
        self.project_semantic(fact, semantic, context)
    }
}

impl UserProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        user: super::fact::UserFact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Global {
            return Err("user fact must have global scope".to_string());
        }

        // 2. Authority and signature evidence.
        let signature_need = signature::project::signature_proof_need(
            fact.id,
            crate::protocol::auth::workspace::scope(user.workspace_id),
            fact.id,
            user.signer_public_key,
        )?;
        let invite_need = crate::core::context::ContextNeed::range(
            fact.id,
            "auth_user_invite",
            crate::core::facts::FactScope::Global,
            user.signer_id,
            user.signer_id,
        );
        let waiting = ProjectionOutput::new()
            .need(signature_need.clone())
            .need(invite_need.clone());
        if !signature::project::signature_proof_ready(
            context,
            &signature_need,
            user.workspace_id,
            fact.id,
            user.signer_public_key,
            "user",
        )? {
            return Ok(waiting);
        }
        let Some(invite_fact) = context.payload_for(&invite_need) else {
            return Ok(waiting);
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
            return Err(
                "user signature signer key does not match user_invite public key".to_string(),
            );
        }
        let user_invite_id = invite_fact.id;
        let context_have = context_have_from_needs(context, [&signature_need, &invite_need]);

        // 3. Materialize.
        Ok(share_fact_with_sync(
            ProjectionOutput::new()
                .need(signature_need)
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
