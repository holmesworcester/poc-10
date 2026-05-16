//! Poc-10 invite-server projector.
//!
//! Validates the invite-server fact payload and emits a single `PutRow` atomic
//! intent.
//!
//! Legacy parity gap (intentional): this validates the declared workspace or
//! admin authority through target context, but it still does not unwrap or
//! verify the legacy signed envelope or endpoint_shared signer binding. This
//! will be tightened once signed-fact integration lands.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::event_modules::identity_admin::layout as admin_layout;
use crate::event_modules::identity_matchers;
use crate::event_modules::identity_workspace::layout as workspace_layout;

use super::layout;
use super::rows::invite_server_row;

#[derive(Debug, Clone, Default)]
pub struct InviteServerProjector;

impl InviteServerProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for InviteServerProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if fact.scope != FactScope::Global {
            return Err("invite_server fact must have global scope".to_string());
        }
        let invite_server = layout::decode_fact(&fact.bytes)?;
        if invite_server.workspace_id == [0; 32] {
            return Err("invite_server fact has empty workspace_id".to_string());
        }
        if invite_server.authority_event_id == [0; 32] {
            return Err("invite_server fact has empty authority_event_id".to_string());
        }
        if invite_server.public_key == [0; 32] {
            return Err("invite_server fact has empty public_key".to_string());
        }
        if let Some(need) = authority_need(fact.id, &invite_server, context)? {
            return Ok(ProjectionOutput::new().need(need));
        }
        Ok(ProjectionOutput::new()
            .offer(identity_matchers::invite_server_offer(fact.id))
            .offer(identity_matchers::invite_server_key_offer(
                fact.id,
                invite_server.workspace_id,
                invite_server.public_key,
            ))
            .intent(
                AtomicIntent::PutRow(invite_server_row(fact.id, &invite_server)?).into_intent(),
            ))
    }
}

fn authority_need(
    owner: [u8; 32],
    invite: &super::fact::InviteServerFact,
    context: &ProjectionContext,
) -> Result<Option<ContextNeed>, String> {
    if invite.authority_event_id == invite.workspace_id {
        let need = identity_matchers::exact_need(
            owner,
            identity_matchers::workspace_role(),
            invite.workspace_id,
        );
        let Some(workspace_fact) = context.payload_for(&need) else {
            return Ok(Some(need));
        };
        if workspace_fact.id != invite.workspace_id {
            return Err("invite_server workspace context payload id mismatch".to_string());
        }
        let workspace = workspace_layout::decode_fact(&workspace_fact.bytes)
            .map_err(|_| "invite_server authority is not a workspace fact".to_string())?;
        if workspace.public_key == [0; 32] {
            return Err("invite_server workspace authority has empty public_key".to_string());
        }
        return Ok(None);
    }

    let need = identity_matchers::exact_need(
        owner,
        identity_matchers::admin_role(),
        invite.authority_event_id,
    );
    let Some(admin_fact) = context.payload_for(&need) else {
        return Ok(Some(need));
    };
    if admin_fact.id != invite.authority_event_id {
        return Err("invite_server admin context payload id mismatch".to_string());
    }
    let admin = admin_layout::decode_fact(&admin_fact.bytes)
        .map_err(|_| "invite_server authority must be an admin fact".to_string())?;
    if admin.workspace_id != invite.workspace_id {
        return Err("invite_server admin authority belongs to a different workspace".to_string());
    }
    Ok(None)
}
