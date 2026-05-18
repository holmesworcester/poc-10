//! Device-invite projector.
//!
//! # Security policy (read this once; the code below mirrors it 1:1)
//!
//! A device_invite admits a device's public key into a workspace. The envelope
//! is signed by one of two parties; the inner `user_invite_event_id` field is
//! the discriminant (`Some` -> path A, `None` -> path B).
//!
//! Shape (both paths):
//!   1. Fact has global scope, is a signed envelope of type device_invite.
//!   2. `workspace_id`, `user_authority_event_id`, `public_key` are non-zero.
//!   3. Declare per-path context needs; park if any required payload is absent.
//!   4. The workspace named by the invite exists at that id and decodes.
//!
//! Path A -- UserSigned, `user_invite_event_id = Some(ui)`:
//!   5A. Envelope signer is the named user (`signer_id == user_authority`).
//!   6A. User payload decodes as a signed user fact at that id.
//!   7A. Envelope signing key equals the user's published `public_key`.
//!   8A. User lives in the invite's workspace.
//!   9A. User envelope was itself signed by the named user_invite `ui`.
//!  10A. User_invite payload decodes at `ui`, lives in the same workspace,
//!       and carries the public_key the user envelope was signed with.
//!
//! Path B -- EndpointSigned, `user_invite_event_id = None`:
//!   5B. Endpoint_shared payload decodes as signed endpoint_shared at
//!       `envelope.signer_id`.
//!   6B. Envelope signing key equals `endpoint.signing_public_key`.
//!   7B. Endpoint and invite agree on workspace_id and user_authority_event_id.
//!
//! On success: emit one PutRow plus device_invite + scoped-key offers.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::event_modules::identity_device_invite::layout;
use crate::event_modules::identity_device_invite::rows::device_invite_row;
use crate::event_modules::identity_endpoint_shared::layout as endpoint_shared_layout;
use crate::event_modules::identity_matchers as m;
use crate::event_modules::identity_user::layout as user_layout;
use crate::event_modules::identity_user_invite::layout as user_invite_layout;
use crate::event_modules::identity_workspace::layout as workspace_layout;
use crate::event_modules::signed_fact;
use crate::projector_experiment::checks::{NeedSet, is_zero32, open_signed, require};

#[derive(Debug, Clone, Default)]
pub struct DeviceInviteProjector;

impl DeviceInviteProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for DeviceInviteProjector {
    fn project(&self, fact: &Fact, ctx: &ProjectionContext) -> Result<ProjectionOutput, String> {
        let owner = fact.id;

        // 1. Shape: scope, signed envelope, device_invite inner type.
        require(fact.scope == FactScope::Global,
            "device_invite fact must have global scope")?;
        let envelope = signed_fact::layout::decode_signed_fact(&fact.bytes)
            .map_err(|_| "device_invite fact must be signed".to_string())?;
        require(envelope.inner_type == layout::TYPE_DEVICE_INVITE,
            "signed fact does not contain a device_invite")?;
        let invite = layout::decode_fact(&envelope.payload)?;

        // 2. Non-zero required fields.
        require(!is_zero32(&invite.workspace_id),
            "device_invite fact has empty workspace_id")?;
        require(!is_zero32(&invite.user_authority_event_id),
            "device_invite fact has empty user_authority_event_id")?;
        require(!is_zero32(&invite.public_key),
            "device_invite fact has empty public_key")?;

        // 3. Declare all per-path needs up front so the wake loop fetches in
        //    parallel; park-on-miss after each fact is looked up.
        let mut needs = NeedSet::new();
        let workspace_need = m::exact_need(owner, m::workspace_role(), invite.workspace_id);
        needs.add(workspace_need.clone());

        match invite.user_invite_event_id {
            // =========================================================
            // Path A: UserSigned
            // =========================================================
            Some(user_invite_id) => {
                let user_need =
                    m::exact_need(owner, m::user_role(), invite.user_authority_event_id);
                let user_invite_need =
                    m::exact_need(owner, m::user_invite_role(), user_invite_id);
                needs.add(user_need.clone());
                needs.add(user_invite_need.clone());
                let (Some(workspace_fact), Some(user_fact), Some(user_invite_fact)) = (
                    ctx.payload_for(&workspace_need),
                    ctx.payload_for(&user_need),
                    ctx.payload_for(&user_invite_need),
                ) else {
                    return Ok(needs.park());
                };

                // 4. Workspace payload: id match + workspace-shaped.
                require(workspace_fact.id == invite.workspace_id,
                    "device_invite workspace context payload id mismatch")?;
                workspace_layout::decode_fact(&workspace_fact.bytes).map_err(|_| {
                    "device_invite workspace dependency is not a workspace".to_string()
                })?;

                // 5A. Envelope signer is the named user authority.
                require(envelope.signer_id == invite.user_authority_event_id,
                    "user-signed device_invite authority must match signer user")?;

                // 6A. User payload decodes as signed user fact at that id.
                require(user_fact.id == invite.user_authority_event_id,
                    "device_invite user context payload id mismatch")?;
                let (user_envelope, user) = open_signed(
                    &user_fact.bytes,
                    user_layout::TYPE_USER,
                    user_layout::decode_fact,
                    "device_invite signer must be user or endpoint_shared",
                    "device_invite user signer payload is invalid",
                )?;

                // 7A. Envelope signing key equals the user's published key.
                require(envelope.signer_public_key == user.public_key,
                    "device_invite signer public key does not match user")?;

                // 8A. User lives in the invite's workspace.
                require(user.workspace_id == invite.workspace_id,
                    "device_invite user authority belongs to a different workspace")?;

                // 9A. User envelope itself was signed by the named user_invite.
                require(user_envelope.signer_id == user_invite_id,
                    "device_invite user_invite dependency does not match signed user")?;

                // 10A. User_invite payload: id, decode, workspace, key chain.
                require(user_invite_fact.id == user_invite_id,
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
            }

            // =========================================================
            // Path B: EndpointSigned
            // =========================================================
            None => {
                let endpoint_need =
                    m::exact_need(owner, m::endpoint_shared_role(), envelope.signer_id);
                needs.add(endpoint_need.clone());
                let (Some(workspace_fact), Some(endpoint_fact)) = (
                    ctx.payload_for(&workspace_need),
                    ctx.payload_for(&endpoint_need),
                ) else {
                    return Ok(needs.park());
                };

                // 4. Workspace payload: id match + workspace-shaped.
                require(workspace_fact.id == invite.workspace_id,
                    "device_invite workspace context payload id mismatch")?;
                workspace_layout::decode_fact(&workspace_fact.bytes).map_err(|_| {
                    "device_invite workspace dependency is not a workspace".to_string()
                })?;

                // 5B. Endpoint_shared payload: id (= signer_id) and decode.
                require(endpoint_fact.id == envelope.signer_id,
                    "device_invite endpoint_shared context payload id mismatch")?;
                let (_, endpoint) = open_signed(
                    &endpoint_fact.bytes,
                    endpoint_shared_layout::TYPE_ENDPOINT_SHARED,
                    endpoint_shared_layout::decode_fact,
                    "device_invite signer must be user or endpoint_shared",
                    "device_invite endpoint_shared signer payload is invalid",
                )?;

                // 6B. Envelope signing key equals endpoint's signing key.
                require(envelope.signer_public_key == endpoint.signing_public_key,
                    "device_invite signer public key does not match endpoint_shared signing key")?;

                // 7B. Endpoint and invite agree on workspace + user_authority.
                require(endpoint.workspace_id == invite.workspace_id,
                    "endpoint_shared-signed device_invite workspace does not match signer")?;
                require(endpoint.user_authority_event_id == invite.user_authority_event_id,
                    "endpoint_shared-signed device_invite user authority does not match signer")?;
            }
        }

        // On success: PutRow + role offer + scoped-key offer, over the needs.
        Ok(needs
            .park()
            .intent(AtomicIntent::PutRow(device_invite_row(owner, &invite)?).into_intent())
            .offer(m::exact_offer(owner, m::device_invite_role()))
            .offer(m::scoped_key_offer(
                owner,
                m::device_invite_key_role(),
                invite.workspace_id,
                m::device_invite_key(invite.user_authority_event_id, invite.public_key),
            )))
    }
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
