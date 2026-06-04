//! Poc-10 endpoint-shared projector.
//!
//! POLICY. An endpoint_shared fact is admitted iff:
//!   1. STRUCTURAL. The outer fact is global, signed, contains endpoint_shared,
//!      and endpoint/workspace/signing fields are valid.
//!   2. AUTHORITY. Device endpoints require device_invite context; invite-server
//!      endpoints require invite_server context. The signer key, workspace, and
//!      user authority must match that grant.
//!   3. MATERIALIZE. Write the endpoint_shared row, publish signer/exact
//!      context, and share the fact with the workspace.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::RowMutation;
use crate::core::pipeline::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
};
use crate::protocol::auth::device_invite;
use crate::protocol::auth::invite_server;
use crate::protocol::sync::shared_fact::project::{context_have_from_needs, share_fact_with_sync};

use super::fact::EndpointRole;
use super::rows::endpoint_shared_row;

#[derive(Debug, Clone, Default)]
pub struct EndpointSharedProjector;

impl EndpointSharedProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for EndpointSharedProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_authenticated::<super::authenticate::EndpointSharedAuthenticator, _>(
            self, fact, context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::EndpointSharedAuthenticator>
    for EndpointSharedProjector
{
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, super::fact::EndpointSharedFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // Authentication (see authenticate.rs) proved canonical bytes, the
        // signer signature, and intrinsic fields. Scope is interpretation, not
        // authentication, so it is checked here, behind the lens and ceiling
        // projector.
        let (fact, shared) = authenticated.into_parts();
        if fact.scope != FactScope::Global {
            return Err("endpoint shared fact must have global scope".to_string());
        }

        // 2. Authority.
        let authority_need = authority_need(fact, &shared, shared.signer_id);
        if !has_valid_authority(&authority_need, &shared, context)? {
            return Ok(ProjectionOutput::new().need(authority_need));
        }
        let context_have = context_have_from_needs(context, [&authority_need]);

        // 3. Materialize.
        Ok(share_fact_with_sync(
            ProjectionOutput::new()
                .need(authority_need)
                .offer(crate::core::context::ContextOffer::range(
                    fact.id,
                    "content_signer",
                    crate::protocol::auth::workspace::scope(shared.workspace_id),
                    shared.endpoint_id,
                    shared.endpoint_id,
                ))
                .offer(crate::core::context::ContextOffer::range(
                    fact.id,
                    "auth_endpoint_shared",
                    crate::core::facts::FactScope::Global,
                    fact.id,
                    fact.id,
                ))
                .row_mutation(RowMutation::PutRow(endpoint_shared_row(fact.id, &shared)?)),
            shared.workspace_id,
            fact,
            context_have,
        ))
    }
}

fn authority_need(
    fact: &Fact,
    shared: &super::fact::EndpointSharedFact,
    signer_id: [u8; 32],
) -> ContextNeed {
    match shared.endpoint_role {
        EndpointRole::InviteServer => crate::core::context::ContextNeed::range(
            fact.id,
            "auth_invite_server",
            crate::core::facts::FactScope::Global,
            signer_id,
            signer_id,
        ),
        EndpointRole::Device => crate::core::context::ContextNeed::range(
            fact.id,
            "auth_device_invite",
            crate::core::facts::FactScope::Global,
            signer_id,
            signer_id,
        ),
    }
}

fn has_valid_authority(
    need: &ContextNeed,
    shared: &super::fact::EndpointSharedFact,
    context: &ProjectionContext,
) -> Result<bool, String> {
    let Some(authority_fact) = context.payload_for(need) else {
        return Ok(false);
    };
    if authority_fact.id != shared.signer_id {
        return Err("endpoint_shared authority context payload id mismatch".to_string());
    }
    if authority_fact.scope != FactScope::Global {
        return Err("endpoint_shared authority must have global scope".to_string());
    }
    if shared.endpoint_role == EndpointRole::Device {
        let invite = device_invite::decode_fact_payload(authority_fact.body()).map_err(|_| {
            "endpoint_shared dependency is not a signed endpoint invite".to_string()
        })?;
        if invite.public_key != shared.signer_public_key {
            return Err(
                "endpoint_shared signer public key does not match device_invite".to_string(),
            );
        }
        if invite.workspace_id != shared.workspace_id {
            return Err("endpoint_shared workspace does not match device_invite".to_string());
        }
        if invite.user_authority_fact_id != shared.user_authority_fact_id {
            return Err("endpoint_shared user authority does not match device_invite".to_string());
        }
        return Ok(true);
    }

    let invite_server = invite_server::decode_fact_payload(authority_fact.body())
        .map_err(|_| "endpoint_shared dependency is not a signed endpoint invite".to_string())?;
    if invite_server.workspace_id != shared.workspace_id {
        return Err("endpoint_shared workspace does not match invite_server".to_string());
    }
    if invite_server.public_key != shared.signer_public_key {
        return Err("endpoint_shared signer public key does not match invite_server".to_string());
    }
    if shared.signer_id != shared.user_authority_fact_id {
        return Err("endpoint_shared user authority does not match invite_server".to_string());
    }
    Ok(true)
}
