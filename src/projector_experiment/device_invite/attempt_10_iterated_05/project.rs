//! Device-invite projector, written as two parallel English narratives.
//!
//! Iterated from `attempt_05_freestyle`. The load-bearing features are kept:
//! two self-contained path functions, each preceded by an English "Required
//! corroborating facts" + numbered "Rules" block whose code body mirrors the
//! rules 1:1 via `// Rule N:` markers. The duplication between paths is
//! intentional -- each path stands alone.
//!
//! Iteration changes over attempt_05:
//!   * Shared `checks::*` -- `require`, `is_zero32`, `open_signed`, `NeedSet`
//!     -- replace ad-hoc boilerplate.
//!   * `NeedSet::new()/add/park` symmetrically gathers needs in each path.
//!   * Dispatcher unwraps `user_invite_event_id` once and forwards it, so the
//!     user-signed path no longer has an `.expect()` for an already-checked
//!     invariant.
//!   * Workspace identity is a tiny `check_workspace_payload` helper -- both
//!     paths state "Rule 1: workspace ..." in English but call the same one-
//!     line check in code; the narrative is unchanged, only the boilerplate.
//!   * Signed-envelope decode + inner-type check + payload decode go through
//!     the shared `open_signed::<T>` helper (used 3x).
//!   * `materialize` returns `Result` so the row-encode failure is no longer
//!     a silent `expect`.

use crate::core::facts::{Fact, FactId, FactScope};
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
use crate::projector_experiment::checks::{is_zero32, open_signed, require, NeedSet};

#[derive(Debug, Clone, Default)]
pub struct DeviceInviteProjector;

impl DeviceInviteProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for DeviceInviteProjector {
    fn project(&self, fact: &Fact, ctx: &ProjectionContext) -> Result<ProjectionOutput, String> {
        let (envelope, invite) = open_and_shape_check(fact)?;
        // The `user_invite_event_id` field is the path discriminant:
        // present -> user-signed, absent -> endpoint-signed.
        match invite.user_invite_event_id {
            Some(user_invite_event_id) => {
                project_user_signed(fact.id, &envelope, &invite, user_invite_event_id, ctx)
            }
            None => project_endpoint_signed(fact.id, &envelope, &invite, ctx),
        }
    }
}

// =============================================================================
// Shared preamble. Decodes the envelope, confirms the inner type, and rejects
// obviously-empty required fields. Errors here are about the fact itself, not
// its authority context.
// =============================================================================

fn open_and_shape_check(fact: &Fact) -> Result<(SignedFactEnvelope, DeviceInviteFact), String> {
    require(fact.scope == FactScope::Global,
        "device_invite fact must have global scope")?;
    let envelope = signed_fact::layout::decode_signed_fact(&fact.bytes)
        .map_err(|_| "device_invite fact must be signed".to_string())?;
    require(envelope.inner_type == layout::TYPE_DEVICE_INVITE,
        "signed fact does not contain a device_invite")?;
    let invite = layout::decode_fact(&envelope.payload)?;
    require(!is_zero32(&invite.workspace_id),
        "device_invite fact has empty workspace_id")?;
    require(!is_zero32(&invite.user_authority_event_id),
        "device_invite fact has empty user_authority_event_id")?;
    require(!is_zero32(&invite.public_key),
        "device_invite fact has empty public_key")?;
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
    owner: FactId,
    envelope: &SignedFactEnvelope,
    invite: &DeviceInviteFact,
    user_invite_event_id: FactId,
    ctx: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let user_authority_event_id = invite.user_authority_event_id;

    let workspace_need = m::exact_need(owner, m::workspace_role(), invite.workspace_id);
    let user_need = m::exact_need(owner, m::user_role(), user_authority_event_id);
    let user_invite_need = m::exact_need(owner, m::user_invite_role(), user_invite_event_id);

    let mut needs = NeedSet::new();
    needs.add(workspace_need.clone());
    needs.add(user_need.clone());
    needs.add(user_invite_need.clone());

    let (Some(workspace_fact), Some(user_fact), Some(user_invite_fact)) = (
        ctx.payload_for(&workspace_need),
        ctx.payload_for(&user_need),
        ctx.payload_for(&user_invite_need),
    ) else {
        return Ok(needs.park());
    };

    // Rule 1: workspace payload matches by id and is workspace-shaped.
    check_workspace_payload(workspace_fact, invite.workspace_id)?;

    // Rule 2: signer must claim to be the named user authority.
    require(envelope.signer_id == user_authority_event_id,
        "user-signed device_invite authority must match signer user")?;

    // Rule 3: user payload matches by id and decodes as a signed user.
    require(user_fact.id == user_authority_event_id,
        "device_invite user context payload id mismatch")?;
    let (user_envelope, user) = open_signed(
        &user_fact.bytes,
        user_layout::TYPE_USER,
        user_layout::decode_fact,
        "device_invite signer must be user or endpoint_shared",
        "device_invite user signer payload is invalid",
    )?;

    // Rule 4: signer key matches the user's published public key.
    require(envelope.signer_public_key == user.public_key,
        "device_invite signer public key does not match user")?;

    // Rule 5: user belongs to the workspace the invite names.
    require(user.workspace_id == invite.workspace_id,
        "device_invite user authority belongs to a different workspace")?;

    // Rule 6: the user envelope was signed by the user_invite the invite names.
    require(user_envelope.signer_id == user_invite_event_id,
        "device_invite user_invite dependency does not match signed user")?;

    // Rule 7: user_invite payload checks out (id, type, workspace, public key).
    require(user_invite_fact.id == user_invite_event_id,
        "device_invite user_invite context payload id mismatch")?;
    let (_, user_invite) = open_signed(
        &user_invite_fact.bytes,
        user_invite_layout::TYPE_USER_INVITE,
        user_invite_layout::decode_fact,
        "device_invite user_invite dependency is not a user_invite",
        "device_invite user_invite context is not a user_invite fact",
    )?;
    require(user_invite.workspace_id == invite.workspace_id,
        "device_invite user_invite belongs to a different workspace")?;
    require(user_invite.public_key == user_envelope.signer_public_key,
        "device_invite user_invite key does not match user")?;

    materialize(owner, invite, needs.park())
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
//      (the signing key really is the endpoint_shared's signing key).
//   4. endpoint_shared.workspace_id == invite.workspace_id.
//   5. endpoint_shared.user_authority_event_id == invite.user_authority_event_id
//      (the endpoint and the invite agree on which user this is for).
// =============================================================================

fn project_endpoint_signed(
    owner: FactId,
    envelope: &SignedFactEnvelope,
    invite: &DeviceInviteFact,
    ctx: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let workspace_need = m::exact_need(owner, m::workspace_role(), invite.workspace_id);
    let endpoint_need = m::exact_need(owner, m::endpoint_shared_role(), envelope.signer_id);

    let mut needs = NeedSet::new();
    needs.add(workspace_need.clone());
    needs.add(endpoint_need.clone());

    let (Some(workspace_fact), Some(endpoint_fact)) = (
        ctx.payload_for(&workspace_need),
        ctx.payload_for(&endpoint_need),
    ) else {
        return Ok(needs.park());
    };

    // Rule 1: workspace payload matches by id and is workspace-shaped.
    check_workspace_payload(workspace_fact, invite.workspace_id)?;

    // Rule 2: endpoint_shared payload matches by id and decodes as expected.
    require(endpoint_fact.id == envelope.signer_id,
        "device_invite endpoint_shared context payload id mismatch")?;
    let (_, endpoint) = open_signed(
        &endpoint_fact.bytes,
        endpoint_shared_layout::TYPE_ENDPOINT_SHARED,
        endpoint_shared_layout::decode_fact,
        "device_invite signer must be user or endpoint_shared",
        "device_invite endpoint_shared signer payload is invalid",
    )?;

    // Rule 3: signer key matches the endpoint_shared's signing key.
    require(envelope.signer_public_key == endpoint.signing_public_key,
        "device_invite signer public key does not match endpoint_shared signing key")?;

    // Rule 4: workspace agreement.
    require(endpoint.workspace_id == invite.workspace_id,
        "endpoint_shared-signed device_invite workspace does not match signer")?;

    // Rule 5: user-authority agreement.
    require(endpoint.user_authority_event_id == invite.user_authority_event_id,
        "endpoint_shared-signed device_invite user authority does not match signer")?;

    materialize(owner, invite, needs.park())
}

// =============================================================================
// Shared mechanics.
// =============================================================================

/// Workspace identity check used by both paths (their English Rule 1).
fn check_workspace_payload(workspace_fact: &Fact, expected_id: FactId) -> Result<(), String> {
    require(workspace_fact.id == expected_id,
        "device_invite workspace context payload id mismatch")?;
    workspace_layout::decode_fact(&workspace_fact.bytes)
        .map_err(|_| "device_invite workspace dependency is not a workspace".to_string())?;
    Ok(())
}

/// On success: emit the PutRow intent and both outbound offers on top of the
/// path's accumulated needs.
fn materialize(
    owner: FactId,
    invite: &DeviceInviteFact,
    parked: ProjectionOutput,
) -> Result<ProjectionOutput, String> {
    let row = AtomicIntent::PutRow(device_invite_row(owner, invite)?).into_intent();
    Ok(parked
        .intent(row)
        .offer(m::exact_offer(owner, m::device_invite_role()))
        .offer(m::scoped_key_offer(
            owner,
            m::device_invite_key_role(),
            invite.workspace_id,
            m::device_invite_key(invite.user_authority_event_id, invite.public_key),
        )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::projector_experiment::device_invite::shared;

    #[test]
    fn passes_full_invariant_battery() {
        shared::run_all_invariants(&DeviceInviteProjector::new());
    }
}
