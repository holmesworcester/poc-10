//! Device-invite projector, written as two parallel English narratives.
//!
//! Idiom: a device-invite has exactly two issuing paths -- a user issues one
//! for their own new device, or an already-trusted endpoint_shared issues one
//! on the user's behalf. Each path is a self-contained function whose body
//! reads top-to-bottom as the security policy for that path. Both narratives
//! follow the same shape: open the envelope, declare authorities the path
//! needs, park until they arrive, then check the rules and emit the row.
//!
//! `project()` is two lines of dispatch over which path applies. A newcomer
//! who reads `project_user_signed` once and then `project_endpoint_signed`
//! understands the whole policy: no traits, no enums-with-methods, no macros,
//! no DSL, no shared "Authorities" type. Repetition between the two paths is
//! intentional -- linear readability beats DRY when the policy itself is
//! short.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::event_modules::identity_device_invite::fact::DeviceInviteFact;
use crate::event_modules::identity_device_invite::layout;
use crate::event_modules::identity_device_invite::rows::device_invite_row;
use crate::event_modules::identity_endpoint_shared::layout as endpoint_shared_layout;
use crate::event_modules::identity_matchers as m;
use crate::event_modules::identity_user::layout as user_layout;
use crate::event_modules::identity_user_invite::layout as user_invite_layout;
use crate::event_modules::identity_workspace::layout as workspace_layout;
use crate::event_modules::signed_fact;
use crate::event_modules::signed_fact::fact::SignedFactEnvelope;

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
        let (envelope, invite) = open_and_shape_check(fact)?;
        // The `user_invite_event_id` field on a device-invite is exactly the
        // path discriminant: present -> user-signed, absent -> endpoint-signed.
        match invite.user_invite_event_id {
            Some(_) => project_user_signed(fact.id, &envelope, &invite, context),
            None => project_endpoint_signed(fact.id, &envelope, &invite, context),
        }
    }
}

// =============================================================================
// Shared preamble: decode the envelope, basic shape checks. Run once at the
// top of `project()` so the path functions below can assume a sane invite.
// =============================================================================

/// Open the signed envelope, confirm it really carries a device-invite, decode
/// the inner fact, and reject obviously-empty required fields. Errors here are
/// about the fact itself, not its authority context.
fn open_and_shape_check(fact: &Fact) -> Result<(SignedFactEnvelope, DeviceInviteFact), String> {
    if fact.scope != FactScope::Global {
        return Err("device_invite fact must have global scope".into());
    }
    let envelope = signed_fact::layout::decode_signed_fact(&fact.bytes)
        .map_err(|_| "device_invite fact must be signed".to_string())?;
    if envelope.inner_type != layout::TYPE_DEVICE_INVITE {
        return Err("signed fact does not contain a device_invite".into());
    }
    let invite = layout::decode_fact(&envelope.payload)?;
    if invite.workspace_id == [0; 32] {
        return Err("device_invite fact has empty workspace_id".into());
    }
    if invite.user_authority_event_id == [0; 32] {
        return Err("device_invite fact has empty user_authority_event_id".into());
    }
    if invite.public_key == [0; 32] {
        return Err("device_invite fact has empty public_key".into());
    }
    Ok((envelope, invite))
}

// =============================================================================
// Path A: the invite was signed by the user themselves.
//
// Required corroborating facts:
//   - workspace          (named by invite.workspace_id)
//   - user               (named by invite.user_authority_event_id)
//   - user_invite        (named by invite.user_invite_event_id)
//
// Rules (each rule is one block of code below, in this order):
//   1. The workspace payload matches by id and is workspace-shaped.
//   2. envelope.signer_id == invite.user_authority_event_id
//      (the signer claims to be the named user authority).
//   3. The user payload matches by id and decodes as a signed user.
//   4. envelope.signer_public_key == user.public_key
//      (the signing key really is the user's published key).
//   5. user.workspace_id == invite.workspace_id
//      (the user lives in the same workspace the invite names).
//   6. The user envelope was itself signed by `invite.user_invite_event_id`
//      (i.e. the invite chain that originally admitted this user).
//   7. The user_invite payload matches by id, decodes as a user_invite,
//      lives in the same workspace, and carries the public key that the user
//      envelope was signed with.
// =============================================================================

fn project_user_signed(
    owner: [u8; 32],
    envelope: &SignedFactEnvelope,
    invite: &DeviceInviteFact,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let user_authority_event_id = invite.user_authority_event_id;
    let user_invite_event_id = invite
        .user_invite_event_id
        .expect("user-signed path: caller checked");

    let workspace_need = m::exact_need(owner, m::workspace_role(), invite.workspace_id);
    let user_need = m::exact_need(owner, m::user_role(), user_authority_event_id);
    let user_invite_need = m::exact_need(owner, m::user_invite_role(), user_invite_event_id);

    // Park until every needed payload has arrived.
    let park = ProjectionOutput::new()
        .need(workspace_need.clone())
        .need(user_need.clone())
        .need(user_invite_need.clone());
    let (Some(workspace_fact), Some(user_fact), Some(user_invite_fact)) = (
        context.payload_for(&workspace_need),
        context.payload_for(&user_need),
        context.payload_for(&user_invite_need),
    ) else {
        return Ok(park);
    };

    // Rule 1: workspace payload matches by id and is workspace-shaped.
    if workspace_fact.id != invite.workspace_id {
        return Err("device_invite workspace context payload id mismatch".into());
    }
    if workspace_layout::decode_fact(&workspace_fact.bytes).is_err() {
        return Err("device_invite workspace dependency is not a workspace".into());
    }

    // Rule 2: signer must claim to be the named user authority.
    if envelope.signer_id != user_authority_event_id {
        return Err("user-signed device_invite authority must match signer user".into());
    }

    // Rule 3: user payload matches by id and decodes as a signed user.
    if user_fact.id != user_authority_event_id {
        return Err("device_invite user context payload id mismatch".into());
    }
    let user_envelope = signed_fact::layout::decode_signed_fact(&user_fact.bytes)
        .map_err(|_| "device_invite signer must be user or endpoint_shared".to_string())?;
    if user_envelope.inner_type != user_layout::TYPE_USER {
        return Err("device_invite signer must be user or endpoint_shared".into());
    }
    let user = user_layout::decode_fact(&user_envelope.payload)
        .map_err(|_| "device_invite user signer payload is invalid".to_string())?;

    // Rule 4: signer key matches the user's published public key.
    if envelope.signer_public_key != user.public_key {
        return Err("device_invite signer public key does not match user".into());
    }

    // Rule 5: user belongs to the workspace the invite names.
    if user.workspace_id != invite.workspace_id {
        return Err("device_invite user authority belongs to a different workspace".into());
    }

    // Rule 6: the user envelope was signed by the user_invite the invite names.
    if user_envelope.signer_id != user_invite_event_id {
        return Err("device_invite user_invite dependency does not match signed user".into());
    }

    // Rule 7: user_invite payload checks out (id, type, workspace, public key).
    if user_invite_fact.id != user_invite_event_id {
        return Err("device_invite user_invite context payload id mismatch".into());
    }
    let user_invite_envelope = signed_fact::layout::decode_signed_fact(&user_invite_fact.bytes)
        .map_err(|_| "device_invite user_invite dependency is not a user_invite".to_string())?;
    if user_invite_envelope.inner_type != user_invite_layout::TYPE_USER_INVITE {
        return Err("device_invite user_invite dependency is not a user_invite".into());
    }
    let user_invite = user_invite_layout::decode_fact(&user_invite_envelope.payload)
        .map_err(|_| "device_invite user_invite payload is invalid".to_string())?;
    if user_invite.workspace_id != invite.workspace_id {
        return Err("device_invite user_invite belongs to a different workspace".into());
    }
    if user_invite.public_key != user_envelope.signer_public_key {
        return Err("device_invite user_invite key does not match user".into());
    }

    Ok(materialize(owner, invite, park))
}

// =============================================================================
// Path B: the invite was signed by an existing endpoint_shared.
//
// Required corroborating facts:
//   - workspace          (named by invite.workspace_id)
//   - endpoint_shared    (named by envelope.signer_id)
//
// Rules:
//   1. The workspace payload exists and matches by id and shape.
//   2. The endpoint_shared payload exists, matches by id (= envelope.signer_id),
//      and decodes as a signed endpoint_shared fact.
//   3. envelope.signer_public_key == endpoint_shared.signing_public_key
//      (the signing key really is the endpoint_shared's signing key)
//   4. endpoint_shared.workspace_id == invite.workspace_id
//   5. endpoint_shared.user_authority_event_id == invite.user_authority_event_id
//      (the endpoint and the invite agree on which user this is for)
// =============================================================================

fn project_endpoint_signed(
    owner: [u8; 32],
    envelope: &SignedFactEnvelope,
    invite: &DeviceInviteFact,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let workspace_need = m::exact_need(owner, m::workspace_role(), invite.workspace_id);
    let endpoint_need = m::exact_need(owner, m::endpoint_shared_role(), envelope.signer_id);

    // Park until every needed payload has arrived.
    let park = ProjectionOutput::new()
        .need(workspace_need.clone())
        .need(endpoint_need.clone());
    let (Some(workspace_fact), Some(endpoint_fact)) = (
        context.payload_for(&workspace_need),
        context.payload_for(&endpoint_need),
    ) else {
        return Ok(park);
    };

    // Rule 1: workspace payload matches by id and is workspace-shaped.
    if workspace_fact.id != invite.workspace_id {
        return Err("device_invite workspace context payload id mismatch".into());
    }
    if workspace_layout::decode_fact(&workspace_fact.bytes).is_err() {
        return Err("device_invite workspace dependency is not a workspace".into());
    }

    // Rule 2: endpoint_shared payload matches by id and decodes as expected.
    if endpoint_fact.id != envelope.signer_id {
        return Err("device_invite endpoint_shared context payload id mismatch".into());
    }
    let endpoint_envelope = signed_fact::layout::decode_signed_fact(&endpoint_fact.bytes)
        .map_err(|_| "device_invite signer must be user or endpoint_shared".to_string())?;
    if endpoint_envelope.inner_type != endpoint_shared_layout::TYPE_ENDPOINT_SHARED {
        return Err("device_invite signer must be user or endpoint_shared".into());
    }
    let endpoint = endpoint_shared_layout::decode_fact(&endpoint_envelope.payload)
        .map_err(|_| "device_invite endpoint_shared payload is invalid".to_string())?;

    // Rule 3: signer key matches the endpoint_shared's signing key.
    if envelope.signer_public_key != endpoint.signing_public_key {
        return Err(
            "device_invite signer public key does not match endpoint_shared signing key".into(),
        );
    }

    // Rule 4 and 5: workspace and user-authority agreement.
    if endpoint.workspace_id != invite.workspace_id {
        return Err("endpoint_shared-signed device_invite workspace does not match signer".into());
    }
    if endpoint.user_authority_event_id != invite.user_authority_event_id {
        return Err(
            "endpoint_shared-signed device_invite user authority does not match signer".into(),
        );
    }

    Ok(materialize(owner, invite, park))
}

// =============================================================================
// Common tail: writing the projected row and the two outbound offers.
//
// `park` already carries the path's needs as the current need-set. We add the
// PutRow intent and the device_invite + device_invite_key offers on top.
// =============================================================================

fn materialize(
    owner: [u8; 32],
    invite: &DeviceInviteFact,
    park: ProjectionOutput,
) -> ProjectionOutput {
    let row = AtomicIntent::PutRow(device_invite_row(owner, invite).expect("encode row"))
        .into_intent();
    park.intent(row)
        .offer(m::exact_offer(owner, m::device_invite_role()))
        .offer(m::scoped_key_offer(
            owner,
            m::device_invite_key_role(),
            invite.workspace_id,
            m::device_invite_key(invite.user_authority_event_id, invite.public_key),
        ))
}

// =============================================================================
// Tests: plug into the shared invariant battery.
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projector_experiment::device_invite::shared;

    #[test]
    fn passes_full_invariant_battery() {
        shared::run_all_invariants(&DeviceInviteProjector::new());
    }
}
