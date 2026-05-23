//! Poc-10 device-invite projector.
//!
//! POLICY. A device_invite is admitted iff:
//!   1. STRUCTURAL. The outer fact is global, signed, contains a device_invite,
//!      and all selector fields are non-zero.
//!   2. AUTHORITY. The invite follows one of two named authority paths:
//!      user-signed invites require workspace, user, and user_invite context;
//!      endpoint-signed invites require workspace and endpoint_shared context.
//!   3. MATERIALIZE. Once the path validates, write the row, publish exact/key
//!      offers, and mark the fact shareable with the workspace.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::RowMutation;
use crate::core::projectors::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::auth;
use crate::protocol::auth::device_invite::fact::DeviceInviteFact;
use crate::protocol::auth::{endpoint_shared, user, user_invite, workspace};
use crate::protocol::sync::share_fact_with_workspace::share_fact_with_workspace_intent_for_fact;

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
        project_typed::<super::Codec, _>(self, fact, context)
    }
}

impl TypedProjector<super::Codec> for DeviceInviteProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        signed: auth::signed_envelope::SignedPayload<DeviceInviteFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Global {
            return Err("device_invite fact must have global scope".to_string());
        }
        let envelope = signed.envelope;
        let device_invite = signed.payload;
        if device_invite.workspace_id == [0; 32] {
            return Err("device_invite fact has empty workspace_id".to_string());
        }
        if device_invite.user_authority_fact_id == [0; 32] {
            return Err("device_invite fact has empty user_authority_fact_id".to_string());
        }
        if device_invite.public_key == [0; 32] {
            return Err("device_invite fact has empty public_key".to_string());
        }

        // 2. Authority.
        //
        // `user_invite_fact_id` is the authority-chain discriminator:
        // Some(id) means the device invite must be signed by the user fact
        // authorized by that user_invite; None means it must be signed by an
        // already-trusted endpoint_shared fact for the same user/workspace.
        match device_invite.user_invite_fact_id {
            Some(user_invite_fact_id) => project_user_signed(
                fact,
                &device_invite,
                &envelope,
                user_invite_fact_id,
                context,
            ),
            None => project_endpoint_signed(fact, &device_invite, &envelope, context),
        }
    }
}

fn project_user_signed(
    fact: &Fact,
    invite: &DeviceInviteFact,
    envelope: &auth::signed_envelope::fact::SignedEnvelope,
    user_invite_fact_id: FactId,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let needs = UserSignedNeeds::new(fact.id, invite, user_invite_fact_id);
    let Some(workspace_fact) = context.payload_for(&needs.workspace) else {
        return Ok(needs.output());
    };
    let Some(user_fact) = context.payload_for(&needs.user) else {
        return Ok(needs.output());
    };
    let Some(user_invite_fact) = context.payload_for(&needs.user_invite) else {
        return Ok(needs.output());
    };

    validate_workspace_context(workspace_fact, invite.workspace_id)?;

    if envelope.signer_id != invite.user_authority_fact_id {
        return Err("user-signed device_invite authority must match signer user".to_string());
    }
    if user_fact.id != invite.user_authority_fact_id {
        return Err("device_invite user context payload id mismatch".to_string());
    }
    let user_envelope = auth::signed_envelope::decode_envelope(user_fact.body())
        .map_err(|_| "device_invite signer must be user or endpoint_shared".to_string())?;
    if user_envelope.inner_type != user::TYPE_USER {
        return Err("device_invite signer must be user or endpoint_shared".to_string());
    }
    let user = user::decode_fact_payload(&user_envelope.payload)
        .map_err(|_| "device_invite user signer payload is invalid".to_string())?;
    if envelope.signer_public_key != user.public_key {
        return Err("device_invite signer public key does not match user".to_string());
    }
    if user.workspace_id != invite.workspace_id {
        return Err("device_invite user authority belongs to a different workspace".to_string());
    }

    if user_envelope.signer_id != user_invite_fact_id {
        return Err("device_invite user_invite dependency does not match signed user".to_string());
    }
    if user_invite_fact.id != user_invite_fact_id {
        return Err("device_invite user_invite context payload id mismatch".to_string());
    }
    let invite_envelope = auth::signed_envelope::decode_envelope(user_invite_fact.body())
        .map_err(|_| "device_invite user_invite context is not a user_invite fact".to_string())?;
    if invite_envelope.inner_type != user_invite::TYPE_USER_INVITE {
        return Err("device_invite user_invite dependency is not a user_invite".to_string());
    }
    let user_invite = user_invite::decode_fact_payload(&invite_envelope.payload)
        .map_err(|_| "device_invite user_invite context is not a user_invite fact".to_string())?;
    if user_invite.workspace_id != invite.workspace_id {
        return Err("device_invite user_invite belongs to a different workspace".to_string());
    }
    if user_invite.public_key != user_envelope.signer_public_key {
        return Err("device_invite user_invite key does not match user".to_string());
    }
    auth::signed_envelope::verify_envelope(envelope)?;

    // 3. Materialize.
    materialized_output(fact, invite, needs.output())
}

fn project_endpoint_signed(
    fact: &Fact,
    invite: &DeviceInviteFact,
    envelope: &auth::signed_envelope::fact::SignedEnvelope,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let needs = EndpointSignedNeeds::new(fact.id, invite, envelope.signer_id);
    let Some(workspace_fact) = context.payload_for(&needs.workspace) else {
        return Ok(needs.output());
    };
    let Some(signer_fact) = context.payload_for(&needs.endpoint_shared) else {
        return Ok(needs.output());
    };

    validate_workspace_context(workspace_fact, invite.workspace_id)?;

    if signer_fact.id != envelope.signer_id {
        return Err("device_invite endpoint_shared context payload id mismatch".to_string());
    }
    let signer_envelope = auth::signed_envelope::decode_envelope(signer_fact.body())
        .map_err(|_| "device_invite signer must be user or endpoint_shared".to_string())?;
    if signer_envelope.inner_type != endpoint_shared::TYPE_ENDPOINT_SHARED {
        return Err("device_invite signer must be user or endpoint_shared".to_string());
    }
    let signer = endpoint_shared::decode_fact_payload(&signer_envelope.payload)
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
    if signer.user_authority_fact_id != invite.user_authority_fact_id {
        return Err(
            "endpoint_shared-signed device_invite user authority does not match signer".to_string(),
        );
    }
    auth::signed_envelope::verify_envelope(envelope)?;

    // 3. Materialize.
    materialized_output(fact, invite, needs.output())
}

struct UserSignedNeeds {
    workspace: ContextNeed,
    user: ContextNeed,
    user_invite: ContextNeed,
}

impl UserSignedNeeds {
    fn new(owner: FactId, invite: &DeviceInviteFact, user_invite_fact_id: FactId) -> Self {
        Self {
            workspace: crate::core::context::ContextNeed::range(
                owner,
                "auth_workspace",
                crate::core::facts::FactScope::Global,
                invite.workspace_id,
                invite.workspace_id,
            ),
            user: crate::core::context::ContextNeed::range(
                owner,
                "auth_user",
                crate::core::facts::FactScope::Global,
                invite.user_authority_fact_id,
                invite.user_authority_fact_id,
            ),
            user_invite: crate::core::context::ContextNeed::range(
                owner,
                "auth_user_invite",
                crate::core::facts::FactScope::Global,
                user_invite_fact_id,
                user_invite_fact_id,
            ),
        }
    }

    fn output(&self) -> ProjectionOutput {
        ProjectionOutput::new()
            .need(self.workspace.clone())
            .need(self.user.clone())
            .need(self.user_invite.clone())
    }
}

struct EndpointSignedNeeds {
    workspace: ContextNeed,
    endpoint_shared: ContextNeed,
}

impl EndpointSignedNeeds {
    fn new(owner: FactId, invite: &DeviceInviteFact, signer_id: FactId) -> Self {
        Self {
            workspace: crate::core::context::ContextNeed::range(
                owner,
                "auth_workspace",
                crate::core::facts::FactScope::Global,
                invite.workspace_id,
                invite.workspace_id,
            ),
            endpoint_shared: crate::core::context::ContextNeed::range(
                owner,
                "auth_endpoint_shared",
                crate::core::facts::FactScope::Global,
                signer_id,
                signer_id,
            ),
        }
    }

    fn output(&self) -> ProjectionOutput {
        ProjectionOutput::new()
            .need(self.workspace.clone())
            .need(self.endpoint_shared.clone())
    }
}

fn validate_workspace_context(workspace_fact: &Fact, workspace_id: FactId) -> Result<(), String> {
    if workspace_fact.id != workspace_id {
        return Err("device_invite workspace context payload id mismatch".to_string());
    }
    workspace::decode_fact_payload(workspace_fact.body())
        .map_err(|_| "device_invite workspace dependency is not a workspace".to_string())?;
    Ok(())
}

fn materialized_output(
    fact: &Fact,
    invite: &DeviceInviteFact,
    output: ProjectionOutput,
) -> Result<ProjectionOutput, String> {
    let device_invite_key = device_invite_key(invite.user_authority_fact_id, invite.public_key);
    Ok(output
        .row_mutation(RowMutation::PutRow(device_invite_row(fact.id, invite)?))
        .offer(crate::core::context::ContextOffer::range(
            fact.id,
            "auth_device_invite",
            crate::core::facts::FactScope::Global,
            fact.id,
            fact.id,
        ))
        .offer(crate::core::context::ContextOffer::range(
            fact.id,
            "auth_device_invite_key",
            crate::protocol::auth::workspace::scope(invite.workspace_id),
            device_invite_key.clone(),
            device_invite_key,
        ))
        .intent(share_fact_with_workspace_intent_for_fact(
            invite.workspace_id,
            fact,
        )))
}

fn device_invite_key(user_authority_fact_id: FactId, public_key: [u8; 32]) -> Vec<u8> {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&user_authority_fact_id);
    key.extend_from_slice(&public_key);
    key
}
