//! Device-invite projector, written inline and flat in a single `project`.
//!
//! Honest assessment after two passes:
//!
//! v1 used a local `enum AuthorityNeed` carried from need-declaration into
//! validation. v2 (this file) drops the enum and uses one top-level
//! `if let Some(user_invite_event_id) = invite.user_invite_event_id { ... }
//! else { ... }`. Each arm is a contiguous block: declare its needs, park if
//! the payload is missing, otherwise validate. Reading top-to-bottom, the
//! reader sees scope, decode, structural checks, workspace authority, then
//! one of two arms. No helpers, no enums, no `needs[1]`-indexing tricks.
//!
//! Compared to the helper-split baseline, this wins on locality: every error
//! string lives next to the check that produces it; the workspace dependency
//! is decoded once at the top instead of inside `validate_authority`; the
//! parking shape (`Ok(output)`) is visible at each park-on-miss point.
//!
//! Cost: the function is twice as tall as baseline's `project`. Inside one
//! arm that doesn't bite, because each arm is its own self-contained story.
//! The shape that hurt most in the helper version was needing to know
//! `needs[1]` meant `user` in one branch and `endpoint_shared` in the other;
//! inlining makes both arms unambiguously named.
//!
//! Verdict: inline-flat beats helpers here. There was no reuse to amortise
//! the helpers; the only caller was `project`, and the indirection mostly
//! hid which need index meant what. The natural axis is the
//! `user_invite_event_id` Option, and making that the top-level branch
//! inside one function is the right shape.

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::event_modules::identity_device_invite::{layout, rows::device_invite_row};
use crate::event_modules::identity_endpoint_shared::layout as endpoint_shared_layout;
use crate::event_modules::identity_matchers;
use crate::event_modules::identity_user::layout as user_layout;
use crate::event_modules::identity_user_invite::layout as user_invite_layout;
use crate::event_modules::identity_workspace::layout as workspace_layout;
use crate::event_modules::signed_fact;

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
        // --- structural decode: scope, signed envelope, inner fact ------------
        if fact.scope != FactScope::Global {
            return Err("device_invite fact must have global scope".to_string());
        }
        let envelope = signed_fact::layout::decode_signed_fact(&fact.bytes)
            .map_err(|_| "device_invite fact must be signed".to_string())?;
        if envelope.inner_type != layout::TYPE_DEVICE_INVITE {
            return Err("signed fact does not contain a device_invite".to_string());
        }
        let invite = layout::decode_fact(&envelope.payload)?;
        if invite.workspace_id == [0; 32] {
            return Err("device_invite fact has empty workspace_id".to_string());
        }
        if invite.user_authority_event_id == [0; 32] {
            return Err("device_invite fact has empty user_authority_event_id".to_string());
        }
        if invite.public_key == [0; 32] {
            return Err("device_invite fact has empty public_key".to_string());
        }

        // --- workspace dependency (required for both authority arms) ----------
        let workspace_need = identity_matchers::exact_need(
            fact.id,
            identity_matchers::workspace_role(),
            invite.workspace_id,
        );

        // user_invite_event_id present -> the user themself signed the invite,
        //   so we also need the user and that user_invite.
        // absent -> an endpoint_shared signer signed it, so we need that
        //   endpoint_shared fact instead.
        if let Some(user_invite_event_id) = invite.user_invite_event_id {
            let user_need = identity_matchers::exact_need(
                fact.id,
                identity_matchers::user_role(),
                invite.user_authority_event_id,
            );
            let user_invite_need = identity_matchers::exact_need(
                fact.id,
                identity_matchers::user_invite_role(),
                user_invite_event_id,
            );
            let parked = ProjectionOutput::new()
                .need(workspace_need.clone())
                .need(user_need.clone())
                .need(user_invite_need.clone());

            // workspace context
            let Some(workspace_fact) = context.payload_for(&workspace_need) else {
                return Ok(parked);
            };
            if workspace_fact.id != invite.workspace_id {
                return Err("device_invite workspace context payload id mismatch".to_string());
            }
            workspace_layout::decode_fact(&workspace_fact.bytes)
                .map_err(|_| "device_invite workspace dependency is not a workspace".to_string())?;

            // envelope must be signed by the user named as authority
            if envelope.signer_id != invite.user_authority_event_id {
                return Err(
                    "user-signed device_invite authority must match signer user".to_string(),
                );
            }

            // user context: id, inner type, key match, workspace match
            let Some(user_fact) = context.payload_for(&user_need) else {
                return Ok(parked);
            };
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
                return Err(
                    "device_invite user authority belongs to a different workspace".to_string(),
                );
            }

            // user_invite context: chain to user, id, inner type, workspace, key
            if user_envelope.signer_id != user_invite_event_id {
                return Err(
                    "device_invite user_invite dependency does not match signed user".to_string(),
                );
            }
            let Some(user_invite_fact) = context.payload_for(&user_invite_need) else {
                return Ok(parked);
            };
            if user_invite_fact.id != user_invite_event_id {
                return Err("device_invite user_invite context payload id mismatch".to_string());
            }
            let user_invite_envelope = signed_fact::layout::decode_signed_fact(
                &user_invite_fact.bytes,
            )
            .map_err(|_| "device_invite user_invite context is not a user_invite fact".to_string())?;
            if user_invite_envelope.inner_type != user_invite_layout::TYPE_USER_INVITE {
                return Err(
                    "device_invite user_invite dependency is not a user_invite".to_string(),
                );
            }
            let user_invite = user_invite_layout::decode_fact(&user_invite_envelope.payload)
                .map_err(|_| {
                    "device_invite user_invite context is not a user_invite fact".to_string()
                })?;
            if user_invite.workspace_id != invite.workspace_id {
                return Err(
                    "device_invite user_invite belongs to a different workspace".to_string(),
                );
            }
            if user_invite.public_key != user_envelope.signer_public_key {
                return Err("device_invite user_invite key does not match user".to_string());
            }
        } else {
            let endpoint_need = identity_matchers::exact_need(
                fact.id,
                identity_matchers::endpoint_shared_role(),
                envelope.signer_id,
            );
            let parked = ProjectionOutput::new()
                .need(workspace_need.clone())
                .need(endpoint_need.clone());

            // workspace context
            let Some(workspace_fact) = context.payload_for(&workspace_need) else {
                return Ok(parked);
            };
            if workspace_fact.id != invite.workspace_id {
                return Err("device_invite workspace context payload id mismatch".to_string());
            }
            workspace_layout::decode_fact(&workspace_fact.bytes)
                .map_err(|_| "device_invite workspace dependency is not a workspace".to_string())?;

            // endpoint_shared context: id, inner type, key match, workspace, user authority
            let Some(endpoint_fact) = context.payload_for(&endpoint_need) else {
                return Ok(parked);
            };
            if endpoint_fact.id != envelope.signer_id {
                return Err(
                    "device_invite endpoint_shared context payload id mismatch".to_string(),
                );
            }
            let endpoint_envelope = signed_fact::layout::decode_signed_fact(&endpoint_fact.bytes)
                .map_err(|_| "device_invite signer must be user or endpoint_shared".to_string())?;
            if endpoint_envelope.inner_type != endpoint_shared_layout::TYPE_ENDPOINT_SHARED {
                return Err("device_invite signer must be user or endpoint_shared".to_string());
            }
            let endpoint = endpoint_shared_layout::decode_fact(&endpoint_envelope.payload)
                .map_err(|_| "device_invite endpoint_shared signer payload is invalid".to_string())?;
            if envelope.signer_public_key != endpoint.signing_public_key {
                return Err(
                    "device_invite signer public key does not match endpoint_shared signing key"
                        .to_string(),
                );
            }
            if endpoint.workspace_id != invite.workspace_id {
                return Err(
                    "endpoint_shared-signed device_invite workspace does not match signer"
                        .to_string(),
                );
            }
            if endpoint.user_authority_event_id != invite.user_authority_event_id {
                return Err(
                    "endpoint_shared-signed device_invite user authority does not match signer"
                        .to_string(),
                );
            }
        }

        // --- materialize: PutRow + role offer + scoped-key offer --------------
        Ok(ProjectionOutput::new()
            .intent(AtomicIntent::PutRow(device_invite_row(fact.id, &invite)?).into_intent())
            .offer(identity_matchers::exact_offer(
                fact.id,
                identity_matchers::device_invite_role(),
            ))
            .offer(identity_matchers::scoped_key_offer(
                fact.id,
                identity_matchers::device_invite_key_role(),
                invite.workspace_id,
                identity_matchers::device_invite_key(
                    invite.user_authority_event_id,
                    invite.public_key,
                ),
            )))
    }
}
