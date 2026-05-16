//! Poc-10 admin grant projector.
//!
//! Validates the admin fact payload and emits a single `PutRow` atomic intent.
//!
//! Legacy parity gap (intentional): the legacy projector required a signed
//! envelope wrapping the admin payload plus workspace, authority-admin, and
//! user dependencies, and enforced cross-fact authority rules:
//!
//! * bootstrap grants: signer == workspace, `user_fact_id == workspace_id`, and
//!   `admin.public_key == workspace.public_key`,
//! * ongoing grants: signer == authority admin id, signer key == authority
//!   admin public key, authority admin belongs to the same workspace, and
//!   `admin.public_key == user.public_key` for the named user.
//!
//! The target projector now validates the workspace/admin/user context it can
//! request exactly, but it still does not unwrap or verify the legacy signed
//! envelope. The signer/key binding will be tightened once signed_fact
//! verification is wired into the projector trait.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::event_modules::identity_matchers;
use crate::event_modules::identity_user::layout as user_layout;
use crate::event_modules::identity_workspace::layout as workspace_layout;

use super::layout;
use super::rows::admin_row;

#[derive(Debug, Clone, Default)]
pub struct AdminProjector;

impl AdminProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for AdminProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if fact.scope != FactScope::Global {
            return Err("admin fact must have global scope".to_string());
        }
        let admin = layout::decode_fact(&fact.bytes)?;
        if admin.workspace_id == [0u8; 32] {
            return Err("admin workspace_id must not be zero".to_string());
        }
        if admin.public_key == [0u8; 32] {
            return Err("admin public_key must not be zero".to_string());
        }
        if admin.authority_fact_id == [0u8; 32] {
            return Err("admin authority_fact_id must not be zero".to_string());
        }
        if admin.user_fact_id == [0u8; 32] {
            return Err("admin user_fact_id must not be zero".to_string());
        }
        if let Some(need) = authority_need(fact.id, &admin, context)? {
            return Ok(ProjectionOutput::new().need(need));
        }
        Ok(ProjectionOutput::new()
            .offer(identity_matchers::exact_offer(
                fact.id,
                identity_matchers::admin_role(),
            ))
            .intent(AtomicIntent::PutRow(admin_row(fact.id, &admin)?).into_intent()))
    }
}

fn authority_need(
    owner: [u8; 32],
    admin: &super::fact::AdminFact,
    context: &ProjectionContext,
) -> Result<Option<ContextNeed>, String> {
    let workspace_need = identity_matchers::exact_need(
        owner,
        identity_matchers::workspace_role(),
        admin.workspace_id,
    );
    let Some(workspace_fact) = context.payload_for(&workspace_need) else {
        return Ok(Some(workspace_need));
    };
    if workspace_fact.id != admin.workspace_id {
        return Err("admin workspace context payload id mismatch".to_string());
    }
    let workspace = workspace_layout::decode_fact(&workspace_fact.bytes)
        .map_err(|_| "admin workspace dependency must be a workspace fact".to_string())?;

    if admin.authority_fact_id == admin.workspace_id {
        if admin.user_fact_id != admin.workspace_id {
            return Err("workspace admin authority can only bootstrap root admin".to_string());
        }
        if admin.public_key != workspace.public_key {
            return Err("admin public_key does not match root workspace public_key".to_string());
        }
        return Ok(None);
    }

    let authority_need = identity_matchers::exact_need(
        owner,
        identity_matchers::admin_role(),
        admin.authority_fact_id,
    );
    let Some(authority_fact) = context.payload_for(&authority_need) else {
        return Ok(Some(authority_need));
    };
    if authority_fact.id != admin.authority_fact_id {
        return Err("admin authority context payload id mismatch".to_string());
    }
    let authority = layout::decode_fact(&authority_fact.bytes)
        .map_err(|_| "signed admin authority must be an admin fact".to_string())?;
    if authority.workspace_id != admin.workspace_id {
        return Err("admin authority belongs to a different workspace".to_string());
    }

    let user_need =
        identity_matchers::exact_need(owner, identity_matchers::user_role(), admin.user_fact_id);
    let Some(user_fact) = context.payload_for(&user_need) else {
        return Ok(Some(user_need));
    };
    if user_fact.id != admin.user_fact_id {
        return Err("admin user context payload id mismatch".to_string());
    }
    let user = user_layout::decode_fact(&user_fact.bytes)
        .map_err(|_| "admin user dependency must be a user fact".to_string())?;
    if user.workspace_id != admin.workspace_id {
        return Err("admin user belongs to a different workspace".to_string());
    }
    if user.public_key != admin.public_key {
        return Err("admin public_key does not match user public_key".to_string());
    }
    Ok(None)
}
