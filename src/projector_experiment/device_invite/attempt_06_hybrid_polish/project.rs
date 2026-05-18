//! Device-invite projector. Hybrid of attempt_04 (inline-flat) and attempt_05
//! (parallel English narratives), with attempt_02's typed path discriminant.
//!
//! `project()` is a thin orchestrator: decode envelope, decode invite,
//! classify into `InviteAuthority`, dispatch. Each path function below is
//! preceded by an English "Required facts" + "Rules" docstring; its body
//! reads as that contract, one `require(...)?` per cross-field check.

use crate::core::context::ContextNeed;
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

#[derive(Debug, Clone, Default)]
pub struct DeviceInviteProjector;

impl DeviceInviteProjector {
    pub fn new() -> Self {
        Self
    }
}

/// Who signed the device_invite envelope. Each variant carries exactly the
/// fact ids the matching path validates. Classifying once at the top makes
/// the bootstrap-vs-delegated split a typed value, not an
/// `Option<user_invite_event_id>` convention.
#[derive(Debug, Clone, Copy)]
pub enum InviteAuthority {
    /// The invited user signed their own first device. Validation must also
    /// check the user_invite that originally admitted them.
    UserSigned { user_authority: FactId, user_invite: FactId },
    /// An already-trusted endpoint signed on the user's behalf.
    EndpointSigned { signer_endpoint: FactId },
}

impl InviteAuthority {
    fn classify(invite: &DeviceInviteFact, signer_id: FactId) -> Self {
        match invite.user_invite_event_id {
            Some(user_invite) => Self::UserSigned {
                user_authority: invite.user_authority_event_id,
                user_invite,
            },
            None => Self::EndpointSigned { signer_endpoint: signer_id },
        }
    }
}

impl Projector for DeviceInviteProjector {
    fn project(&self, fact: &Fact, ctx: &ProjectionContext) -> Result<ProjectionOutput, String> {
        // Shape: scope, signed envelope, inner type, decode, non-zero fields.
        require(fact.scope == FactScope::Global, "device_invite fact must have global scope")?;
        let envelope = signed_fact::layout::decode_signed_fact(&fact.bytes)
            .map_err(|_| "device_invite fact must be signed".to_string())?;
        require(envelope.inner_type == layout::TYPE_DEVICE_INVITE,
            "signed fact does not contain a device_invite")?;
        let invite = layout::decode_fact(&envelope.payload)?;
        non_zero(&invite.workspace_id, "workspace_id")?;
        non_zero(&invite.user_authority_event_id, "user_authority_event_id")?;
        non_zero(&invite.public_key, "public_key")?;

        // Dispatch on signer type; each path runs its own authority chain.
        match InviteAuthority::classify(&invite, envelope.signer_id) {
            InviteAuthority::UserSigned { user_authority, user_invite } => {
                project_user_signed(fact.id, &envelope, &invite, user_authority, user_invite, ctx)
            }
            InviteAuthority::EndpointSigned { signer_endpoint } => {
                project_endpoint_signed(fact.id, &envelope, &invite, signer_endpoint, ctx)
            }
        }
    }
}

// =============================================================================
// Path A: the invited user signed the device_invite themselves.
//
// Required facts:
//   - workspace      (named by invite.workspace_id)
//   - user           (named by invite.user_authority_event_id)
//   - user_invite    (named by invite.user_invite_event_id)
//
// Rules (each is one `require(...)?` below, in spec order):
//   1. Envelope signer is the named user authority.
//   2. Workspace payload matches by id and is workspace-shaped.
//   3. User payload matches by id and decodes as a signed user.
//   4. Envelope signing key equals the user's published public key.
//   5. The user belongs to the same workspace the invite names.
//   6. The user envelope was signed by the named user_invite.
//   7. The user_invite payload matches by id, decodes as a user_invite,
//      lives in the same workspace, and carries the public key the user
//      envelope was signed with.
// =============================================================================

fn project_user_signed(
    owner: FactId,
    envelope: &SignedFactEnvelope,
    invite: &DeviceInviteFact,
    user_authority: FactId,
    user_invite_id: FactId,
    ctx: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let workspace_need = m::exact_need(owner, m::workspace_role(), invite.workspace_id);
    let user_need = m::exact_need(owner, m::user_role(), user_authority);
    let user_invite_need = m::exact_need(owner, m::user_invite_role(), user_invite_id);
    let parked = park(&[&workspace_need, &user_need, &user_invite_need]);
    let (Some(workspace_fact), Some(user_fact), Some(user_invite_fact)) = (
        ctx.payload_for(&workspace_need),
        ctx.payload_for(&user_need),
        ctx.payload_for(&user_invite_need),
    ) else {
        return Ok(parked);
    };

    // 1. Envelope signer is the named user.
    require(envelope.signer_id == user_authority,
        "user-signed device_invite authority must match signer user")?;

    // 2. Workspace payload.
    check_workspace_payload(workspace_fact, invite.workspace_id)?;

    // 3-5. User payload: id, signed-user shape, signer key match, workspace match.
    require(user_fact.id == user_authority,
        "device_invite user context payload id mismatch")?;
    let (user_envelope, user) = open_signed::<_>(
        &user_fact.bytes,
        user_layout::TYPE_USER,
        user_layout::decode_fact,
        "device_invite signer must be user or endpoint_shared",
        "device_invite user signer payload is invalid",
    )?;
    require(envelope.signer_public_key == user.public_key,
        "device_invite signer public key does not match user")?;
    require(user.workspace_id == invite.workspace_id,
        "device_invite user authority belongs to a different workspace")?;

    // 6-7. User_invite payload: chain id, shape, workspace, key.
    require(user_envelope.signer_id == user_invite_id,
        "device_invite user_invite dependency does not match signed user")?;
    require(user_invite_fact.id == user_invite_id,
        "device_invite user_invite context payload id mismatch")?;
    let (_, user_invite) = open_signed::<_>(
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

    Ok(materialize(owner, invite, parked))
}

// =============================================================================
// Path B: an already-trusted endpoint_shared signed on the user's behalf.
//
// Required facts:
//   - workspace        (named by invite.workspace_id)
//   - endpoint_shared  (named by envelope.signer_id)
//
// Rules:
//   1. Workspace payload matches by id and is workspace-shaped.
//   2. Endpoint_shared payload matches by id (= envelope.signer_id) and
//      decodes as a signed endpoint_shared fact.
//   3. Envelope signing key equals the endpoint_shared's signing key.
//   4. Endpoint and invite agree on workspace_id.
//   5. Endpoint and invite agree on user_authority_event_id.
// =============================================================================

fn project_endpoint_signed(
    owner: FactId,
    envelope: &SignedFactEnvelope,
    invite: &DeviceInviteFact,
    signer_endpoint: FactId,
    ctx: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let workspace_need = m::exact_need(owner, m::workspace_role(), invite.workspace_id);
    let endpoint_need = m::exact_need(owner, m::endpoint_shared_role(), signer_endpoint);
    let parked = park(&[&workspace_need, &endpoint_need]);
    let (Some(workspace_fact), Some(endpoint_fact)) = (
        ctx.payload_for(&workspace_need),
        ctx.payload_for(&endpoint_need),
    ) else {
        return Ok(parked);
    };

    // 1. Workspace payload.
    check_workspace_payload(workspace_fact, invite.workspace_id)?;

    // 2. Endpoint_shared payload: id, signed-endpoint_shared shape.
    require(endpoint_fact.id == signer_endpoint,
        "device_invite endpoint_shared context payload id mismatch")?;
    let (_, endpoint) = open_signed::<_>(
        &endpoint_fact.bytes,
        endpoint_shared_layout::TYPE_ENDPOINT_SHARED,
        endpoint_shared_layout::decode_fact,
        "device_invite signer must be user or endpoint_shared",
        "device_invite endpoint_shared signer payload is invalid",
    )?;

    // 3-5. Signer key, workspace, user-authority agreement.
    require(envelope.signer_public_key == endpoint.signing_public_key,
        "device_invite signer public key does not match endpoint_shared signing key")?;
    require(endpoint.workspace_id == invite.workspace_id,
        "endpoint_shared-signed device_invite workspace does not match signer")?;
    require(endpoint.user_authority_event_id == invite.user_authority_event_id,
        "endpoint_shared-signed device_invite user authority does not match signer")?;

    Ok(materialize(owner, invite, parked))
}

// =============================================================================
// Shared tail: emit the row and offers on top of `parked` (which already
// carries the path's needs).
// =============================================================================

fn materialize(owner: FactId, invite: &DeviceInviteFact, parked: ProjectionOutput) -> ProjectionOutput {
    let row = AtomicIntent::PutRow(device_invite_row(owner, invite).expect("encode row"))
        .into_intent();
    parked
        .intent(row)
        .offer(m::exact_offer(owner, m::device_invite_role()))
        .offer(m::scoped_key_offer(
            owner,
            m::device_invite_key_role(),
            invite.workspace_id,
            m::device_invite_key(invite.user_authority_event_id, invite.public_key),
        ))
}

// =============================================================================
// Micro-helpers. `require` / `non_zero` follow connection_request's
// attempt_03_declarative; `park`, `open_signed`, `check_workspace_payload`
// are local DRY-passes over patterns that appear in both paths.
// =============================================================================

fn require(condition: bool, error: &str) -> Result<(), String> {
    if condition { Ok(()) } else { Err(error.to_string()) }
}

fn non_zero(field: &[u8; 32], name: &str) -> Result<(), String> {
    if field == &[0; 32] {
        return Err(format!("device_invite fact has empty {name}"));
    }
    Ok(())
}

fn park(needs: &[&ContextNeed]) -> ProjectionOutput {
    let mut out = ProjectionOutput::new();
    for need in needs {
        out = out.need((*need).clone());
    }
    out
}

fn check_workspace_payload(workspace_fact: &Fact, expected_id: FactId) -> Result<(), String> {
    require(workspace_fact.id == expected_id,
        "device_invite workspace context payload id mismatch")?;
    workspace_layout::decode_fact(&workspace_fact.bytes)
        .map_err(|_| "device_invite workspace dependency is not a workspace".to_string())?;
    Ok(())
}

/// Open a signed envelope, confirm the inner type tag, and decode the payload.
/// `envelope_err` covers envelope-decode and tag-mismatch failures (since both
/// mean "wrong fact kind here"); `payload_err` covers a malformed inner body.
fn open_signed<T>(
    bytes: &[u8],
    expected_type: u8,
    decode: fn(&[u8]) -> Result<T, String>,
    envelope_err: &str,
    payload_err: &str,
) -> Result<(SignedFactEnvelope, T), String> {
    let envelope = signed_fact::layout::decode_signed_fact(bytes)
        .map_err(|_| envelope_err.to_string())?;
    require(envelope.inner_type == expected_type, envelope_err)?;
    let inner = decode(&envelope.payload).map_err(|_| payload_err.to_string())?;
    Ok((envelope, inner))
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
