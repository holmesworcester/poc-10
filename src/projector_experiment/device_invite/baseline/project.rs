//! Poc-10 device-invite projector.
//!
//! Device invites are signed either by the invited user or by an existing
//! endpoint_shared signer for that user. Projection validates the envelope
//! signer against the matching authority context before writing the invite.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::event_modules::identity_endpoint_shared::layout as endpoint_shared_layout;
use crate::event_modules::identity_matchers;
use crate::event_modules::identity_user::layout as user_layout;
use crate::event_modules::identity_user_invite::layout as user_invite_layout;
use crate::event_modules::identity_workspace::layout as workspace_layout;
use crate::event_modules::signed_fact;

use crate::event_modules::identity_device_invite::layout;
use crate::event_modules::identity_device_invite::rows::device_invite_row;

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
        let envelope = signed_fact::layout::decode_signed_fact(&fact.bytes)
            .map_err(|_| "device_invite fact must be signed".to_string())?;
        if envelope.inner_type != layout::TYPE_DEVICE_INVITE {
            return Err("signed fact does not contain a device_invite".to_string());
        }
        let device_invite = layout::decode_fact(&envelope.payload)?;
        if device_invite.workspace_id == [0; 32] {
            return Err("device_invite fact has empty workspace_id".to_string());
        }
        if device_invite.user_authority_event_id == [0; 32] {
            return Err("device_invite fact has empty user_authority_event_id".to_string());
        }
        if device_invite.public_key == [0; 32] {
            return Err("device_invite fact has empty public_key".to_string());
        }
        let needs = authority_needs(fact.id, &device_invite, envelope.signer_id);
        let output = output_with_needs(&needs);
        if !has_all_context(&needs, context) {
            return Ok(output);
        }
        validate_authority(&needs, &device_invite, &envelope, context)?;
        Ok(output
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

fn authority_needs(
    owner: [u8; 32],
    invite: &crate::event_modules::identity_device_invite::fact::DeviceInviteFact,
    signer_id: [u8; 32],
) -> Vec<crate::core::context::ContextNeed> {
    let workspace_need = identity_matchers::exact_need(
        owner,
        identity_matchers::workspace_role(),
        invite.workspace_id,
    );
    if let Some(user_invite_event_id) = invite.user_invite_event_id {
        vec![
            workspace_need,
            identity_matchers::exact_need(
                owner,
                identity_matchers::user_role(),
                invite.user_authority_event_id,
            ),
            identity_matchers::exact_need(
                owner,
                identity_matchers::user_invite_role(),
                user_invite_event_id,
            ),
        ]
    } else {
        vec![
            workspace_need,
            identity_matchers::exact_need(
                owner,
                identity_matchers::endpoint_shared_role(),
                signer_id,
            ),
        ]
    }
}

fn output_with_needs(needs: &[crate::core::context::ContextNeed]) -> ProjectionOutput {
    let mut output = ProjectionOutput::new();
    for need in needs {
        output = output.need(need.clone());
    }
    output
}

fn has_all_context(
    needs: &[crate::core::context::ContextNeed],
    context: &ProjectionContext,
) -> bool {
    needs.iter().all(|need| context.payload_for(need).is_some())
}

fn validate_authority(
    needs: &[crate::core::context::ContextNeed],
    invite: &crate::event_modules::identity_device_invite::fact::DeviceInviteFact,
    envelope: &signed_fact::fact::SignedFactEnvelope,
    context: &ProjectionContext,
) -> Result<(), String> {
    let workspace_fact = context
        .payload_for(&needs[0])
        .expect("checked by has_all_context");
    if workspace_fact.id != invite.workspace_id {
        return Err("device_invite workspace context payload id mismatch".to_string());
    }
    workspace_layout::decode_fact(&workspace_fact.bytes)
        .map_err(|_| "device_invite workspace dependency is not a workspace".to_string())?;

    if invite.user_invite_event_id.is_none() {
        return validate_endpoint_shared_authority(&needs[1], invite, envelope, context);
    }

    if envelope.signer_id != invite.user_authority_event_id {
        return Err("user-signed device_invite authority must match signer user".to_string());
    }
    let user_need = &needs[1];
    let user_fact = context
        .payload_for(user_need)
        .expect("checked by has_all_context");
    if user_fact.id != invite.user_authority_event_id {
        return Err("device_invite user context payload id mismatch".to_string());
    }
    let user_envelope = signed_fact::layout::decode_signed_fact(&user_fact.bytes)
        .map_err(|_| "device_invite signer must be user or endpoint_shared".to_string())?;
    if user_envelope.inner_type != user_layout::TYPE_USER {
        return Err("device_invite signer must be user or endpoint_shared".to_string());
    }
    let user = user_layout::decode_fact(&user_envelope.payload)
        .map_err(|_| "device_invite user signer payload is invalid".to_string())?;
    if envelope.signer_public_key != user.public_key {
        return Err("device_invite signer public key does not match user".to_string());
    }
    if user.workspace_id != invite.workspace_id {
        return Err("device_invite user authority belongs to a different workspace".to_string());
    }

    if let Some(user_invite_event_id) = invite.user_invite_event_id {
        if user_envelope.signer_id != user_invite_event_id {
            return Err(
                "device_invite user_invite dependency does not match signed user".to_string(),
            );
        }
        let invite_need = &needs[2];
        let invite_fact = context
            .payload_for(invite_need)
            .expect("checked by has_all_context");
        if invite_fact.id != user_invite_event_id {
            return Err("device_invite user_invite context payload id mismatch".to_string());
        }
        let invite_envelope =
            signed_fact::layout::decode_signed_fact(&invite_fact.bytes).map_err(|_| {
                "device_invite user_invite context is not a user_invite fact".to_string()
            })?;
        if invite_envelope.inner_type != user_invite_layout::TYPE_USER_INVITE {
            return Err("device_invite user_invite dependency is not a user_invite".to_string());
        }
        let user_invite =
            user_invite_layout::decode_fact(&invite_envelope.payload).map_err(|_| {
                "device_invite user_invite context is not a user_invite fact".to_string()
            })?;
        if user_invite.workspace_id != invite.workspace_id {
            return Err("device_invite user_invite belongs to a different workspace".to_string());
        }
        if user_invite.public_key != user_envelope.signer_public_key {
            return Err("device_invite user_invite key does not match user".to_string());
        }
    }
    Ok(())
}

fn validate_endpoint_shared_authority(
    need: &crate::core::context::ContextNeed,
    invite: &crate::event_modules::identity_device_invite::fact::DeviceInviteFact,
    envelope: &signed_fact::fact::SignedFactEnvelope,
    context: &ProjectionContext,
) -> Result<(), String> {
    let signer_fact = context
        .payload_for(need)
        .expect("checked by has_all_context");
    if signer_fact.id != envelope.signer_id {
        return Err("device_invite endpoint_shared context payload id mismatch".to_string());
    }
    let signer_envelope = signed_fact::layout::decode_signed_fact(&signer_fact.bytes)
        .map_err(|_| "device_invite signer must be user or endpoint_shared".to_string())?;
    if signer_envelope.inner_type != endpoint_shared_layout::TYPE_ENDPOINT_SHARED {
        return Err("device_invite signer must be user or endpoint_shared".to_string());
    }
    let signer = endpoint_shared_layout::decode_fact(&signer_envelope.payload)
        .map_err(|_| "device_invite endpoint_shared signer payload is invalid".to_string())?;
    if envelope.signer_public_key != signer.signing_public_key {
        return Err(
            "device_invite signer public key does not match endpoint_shared signing key"
                .to_string(),
        );
    }
    if signer.workspace_id != invite.workspace_id {
        return Err(
            "endpoint_shared-signed device_invite workspace does not match signer".to_string(),
        );
    }
    if signer.user_authority_event_id != invite.user_authority_event_id {
        return Err(
            "endpoint_shared-signed device_invite user authority does not match signer".to_string(),
        );
    }
    Ok(())
}

