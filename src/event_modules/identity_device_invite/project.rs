//! Poc-10 device-invite projector.
//!
//! Validates the device-invite fact payload and emits a single `PutRow` atomic
//! intent.
//!
//! Legacy parity gap (intentional): this validates user-signed device invites
//! through exact target needs, but it still does not unwrap or verify the
//! legacy signed envelope. Endpoint-shared-signed device invites require the
//! envelope signer endpoint id/key; the raw target fact does not carry that
//! context, so that path is blocked instead of being projected from guessed
//! authority. The legacy `SendBootstrapRequest` intent emitted by the invite
//! triplet is also deferred until transit handlers land.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::event_modules::identity_matchers;
use crate::event_modules::identity_user::layout as user_layout;
use crate::event_modules::identity_user_invite::layout as user_invite_layout;

use super::layout;
use super::rows::device_invite_row;

#[derive(Debug, Clone, Default)]
pub struct DeviceInviteProjector;

impl DeviceInviteProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for DeviceInviteProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if fact.scope != FactScope::Global {
            return Err("device_invite fact must have global scope".to_string());
        }
        let device_invite = layout::decode_fact(&fact.bytes)?;
        if device_invite.workspace_id == [0; 32] {
            return Err("device_invite fact has empty workspace_id".to_string());
        }
        if device_invite.user_authority_event_id == [0; 32] {
            return Err("device_invite fact has empty user_authority_event_id".to_string());
        }
        if device_invite.public_key == [0; 32] {
            return Err("device_invite fact has empty public_key".to_string());
        }
        if let Some(need) = authority_need(fact.id, &device_invite, context)? {
            return Ok(ProjectionOutput::new().need(need));
        }
        Ok(ProjectionOutput::new()
            .intent(AtomicIntent::PutRow(device_invite_row(fact.id, &device_invite)?).into_intent())
            .offer(identity_matchers::exact_offer(
                fact.id,
                identity_matchers::device_invite_role(),
            ))
            .offer(identity_matchers::scoped_key_offer(
                fact.id,
                identity_matchers::device_invite_key_role(),
                device_invite.workspace_id,
                identity_matchers::device_invite_key(
                    device_invite.user_authority_event_id,
                    device_invite.public_key,
                ),
            )))
    }
}

fn authority_need(
    owner: [u8; 32],
    invite: &super::fact::DeviceInviteFact,
    context: &ProjectionContext,
) -> Result<Option<crate::core::context::ContextNeed>, String> {
    if invite.user_invite_event_id.is_none() {
        return Err(
            "device_invite endpoint_shared authority requires signed envelope context".to_string(),
        );
    }

    let user_need = identity_matchers::exact_need(
        owner,
        identity_matchers::user_role(),
        invite.user_authority_event_id,
    );
    let Some(user_fact) = context.payload_for(&user_need) else {
        return Ok(Some(user_need));
    };
    if user_fact.id != invite.user_authority_event_id {
        return Err("device_invite user context payload id mismatch".to_string());
    }
    let user = user_layout::decode_fact(&user_fact.bytes)
        .map_err(|_| "device_invite authority must be a user fact".to_string())?;
    if user.workspace_id != invite.workspace_id {
        return Err("device_invite user authority belongs to a different workspace".to_string());
    }

    if let Some(user_invite_event_id) = invite.user_invite_event_id {
        let invite_need = identity_matchers::exact_need(
            owner,
            identity_matchers::user_invite_role(),
            user_invite_event_id,
        );
        let Some(invite_fact) = context.payload_for(&invite_need) else {
            return Ok(Some(invite_need));
        };
        if invite_fact.id != user_invite_event_id {
            return Err("device_invite user_invite context payload id mismatch".to_string());
        }
        let user_invite = user_invite_layout::decode_fact(&invite_fact.bytes).map_err(|_| {
            "device_invite user_invite context is not a user_invite fact".to_string()
        })?;
        if user_invite.workspace_id != invite.workspace_id {
            return Err("device_invite user_invite belongs to a different workspace".to_string());
        }
        if user_invite.public_key != user.public_key {
            return Err("device_invite user_invite key does not match user".to_string());
        }
    }
    Ok(None)
}
