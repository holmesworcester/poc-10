//! Poc-10 invite-accepted projector.
//!
//! POLICY. An invite_accepted fact is admitted iff:
//!   1. STRUCTURAL. The fact is local-only and all fact id/hash fields are
//!      non-zero.
//!   2. CONTEXT. No separate local admission metadata is required; the accepted
//!      fact carries the invite-link bootstrap context.
//!   3. MATERIALIZE. Write the invite_accepted row and publish accepted
//!      workspace context for identity-scoped links plus connection bootstrap
//!      context for maintenance. Broader network effects remain explicit
//!      intent-handler work.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::pipeline::{FactPipeline, ProjectionContext, ProjectionOutput, Projector};

use super::{derived_invite_secret_fact_id, invite_accepted_row};

/// Projector route metadata for the invite_accepted fact.
pub const PIPELINE: FactPipeline =
    FactPipeline::projector("auth::invite_accepted::project::InviteAcceptedProjector");

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
        let decoded = super::decode::decode_fact(fact.body())?;
        let authenticated = super::authenticate::authenticate(fact, decoded, context)?;
        let semantic = super::adapt::adapt(authenticated)?;
        self.project_semantic(fact, semantic, context)
    }
}

impl InviteAcceptedProjector {
    fn project_semantic(
        &self,
        fact: &Fact,
        accepted: super::fact::InviteAcceptedFact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Scope.
        if fact.scope != FactScope::Local {
            return Err("invite_accepted fact must have local scope".to_string());
        }

        // 3. Materialize.
        let invite_secret_id = derived_invite_secret_fact_id(&accepted)?;
        let mut output = ProjectionOutput::new()
            .offer(crate::core::context::ContextOffer::range(
                fact.id,
                "connection_invite_secret",
                crate::core::facts::FactScope::Local,
                invite_secret_id,
                invite_secret_id,
            ))
            .row_mutation(RowMutation::PutRow(invite_accepted_row(
                fact.id, &accepted,
            )?));
        if accepted.identity_scope {
            output = output.offer(super::workspace_accepted_offer(
                fact.id,
                accepted.workspace_id,
            ));
        }
        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::auth::endpoint_shared::fact::EndpointRole;
    use crate::protocol::auth::invite::fact::bootstrap_secret_hash;

    #[test]
    fn invite_accepted_offers_accepted_workspace_not_workspace_authority() {
        let (_accepted, accepted_fact) = super::super::author::accepted_fact(
            [1; 32],
            [2; 32],
            bootstrap_secret_hash(&[7; 32]),
            [7; 32],
            [3; 32],
            [4; 32],
            "127.0.0.1:41000".parse().unwrap(),
            None,
            EndpointRole::Device,
            true,
            11,
        )
        .expect("accepted fact");

        let output = InviteAcceptedProjector::new()
            .project(&accepted_fact, &ProjectionContext::default())
            .expect("accepted invite projects");

        assert!(output
            .offers
            .iter()
            .any(|offer| offer.role.as_str() == super::super::AUTH_WORKSPACE_ACCEPTED_ROLE));
        assert!(output
            .offers
            .iter()
            .any(|offer| offer.role.as_str() == "connection_invite_secret"));
        assert!(!output
            .offers
            .iter()
            .any(|offer| offer.role.as_str() == "auth_workspace"));
    }

    #[test]
    fn non_identity_acceptance_does_not_offer_workspace_acceptance() {
        let (_accepted, accepted_fact) = super::super::author::accepted_fact(
            [1; 32],
            [2; 32],
            bootstrap_secret_hash(&[7; 32]),
            [7; 32],
            [3; 32],
            [4; 32],
            "127.0.0.1:41000".parse().unwrap(),
            None,
            EndpointRole::Device,
            false,
            11,
        )
        .expect("accepted fact");

        let output = InviteAcceptedProjector::new()
            .project(&accepted_fact, &ProjectionContext::default())
            .expect("accepted invite projects");

        assert!(!output
            .offers
            .iter()
            .any(|offer| offer.role.as_str() == super::super::AUTH_WORKSPACE_ACCEPTED_ROLE));
        assert!(output
            .offers
            .iter()
            .any(|offer| offer.role.as_str() == "connection_invite_secret"));
    }
}
