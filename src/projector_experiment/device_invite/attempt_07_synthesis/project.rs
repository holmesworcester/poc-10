//! Device-invite projector with `InviteAuthority` as the function's spine.
//!
//! # Angle (synthesis (a), pushed all the way)
//!
//! A device-invite is signed in exactly one of two ways. We make that the
//! ONLY thing the function pivots on, by lifting it into a sum type:
//!
//!     enum InviteAuthority {
//!         UserSigned     { user_authority, user_invite, .. },
//!         EndpointSigned { user_authority, endpoint_signer, .. },
//!     }
//!
//! `project()` then does the same `match` twice:
//!
//!     1. classify (one match)            -> InviteAuthority
//!     2. declare context needs (match)    -> Vec<ContextNeed>
//!     3. fetch payloads + validate (match) -> Result<(), String>
//!     4. emit
//!
//! The two `match` arms are parallel: read step 2 once and you know what each
//! path depends on; read step 3 and you have the full per-path validation
//! policy. Adding a new authority kind is a compile error in three places,
//! all of them the same shape.
//!
//! # Why not freestyle / inline-flat?
//!
//! Freestyle wins on the newcomer test by colocating an English rule block
//! with each path's code. Inline-flat wins on locality. The shape below tries
//! something neither tried: take attempt_02's enum but make it the load-
//! bearing structure for the entire function, so the policy reads as a
//! comparison table between two named variants rather than as two duplicated
//! narratives. The variant names ARE the documentation; arm parallelism is
//! the symmetry the reader is meant to notice.
//!
//! # What this is NOT
//!
//! - Not a state machine: no `Classified -> Validated -> Emitted` chain of
//!   wrapper types. The reviewer flagged that kind of indirection as a loss.
//! - Not policy-as-data: the rules ARE the match arms, not a list traversed
//!   by an interpreter.
//! - Not a typed context wrapper: needs are declared and consumed inline.
//!
//! Every check is visible in `project()`. The only extracted helpers are the
//! envelope decoder (so `project()` opens with the authority, not boilerplate)
//! and the workspace check (shared by both arms; same code, same errors).

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

// =============================================================================
// The spine: who signed this device_invite, and what fact ids does that name?
// =============================================================================

/// Which party signed a device_invite, and the dependency ids that party names.
///
/// `UserSigned`     — invite carries `Some(user_invite_event_id)`; the envelope
///                    is signed by the named user, whose own admission chain
///                    (the `user_invite`) we re-check.
/// `EndpointSigned` — invite carries `None`; the envelope is signed by an
///                    already-projected endpoint_shared that we look up by
///                    `envelope.signer_id`.
#[derive(Debug, Clone, Copy)]
enum InviteAuthority {
    UserSigned {
        workspace_id: FactId,
        user_authority: FactId,
        user_invite: FactId,
    },
    EndpointSigned {
        workspace_id: FactId,
        user_authority: FactId,
        endpoint_signer: FactId,
    },
}

impl InviteAuthority {
    fn classify(invite: &DeviceInviteFact, envelope: &SignedFactEnvelope) -> Self {
        match invite.user_invite_event_id {
            Some(user_invite) => Self::UserSigned {
                workspace_id: invite.workspace_id,
                user_authority: invite.user_authority_event_id,
                user_invite,
            },
            None => Self::EndpointSigned {
                workspace_id: invite.workspace_id,
                user_authority: invite.user_authority_event_id,
                endpoint_signer: envelope.signer_id,
            },
        }
    }
}

// =============================================================================
// project(): one classify, then two parallel matches over the same enum.
// =============================================================================

impl Projector for DeviceInviteProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // ---- step 0: open envelope, shape-check the invite ----
        let (envelope, invite) = open_and_shape_check(fact)?;
        let owner = fact.id;

        // ---- step 1: classify ----
        let authority = InviteAuthority::classify(&invite, &envelope);

        // ---- step 2: declare context needs (per arm; workspace is shared) ----
        let workspace_need = m::exact_need(owner, m::workspace_role(), invite.workspace_id);
        let needs: Vec<ContextNeed> = match authority {
            InviteAuthority::UserSigned { user_authority, user_invite, .. } => vec![
                workspace_need.clone(),
                m::exact_need(owner, m::user_role(), user_authority),
                m::exact_need(owner, m::user_invite_role(), user_invite),
            ],
            InviteAuthority::EndpointSigned { endpoint_signer, .. } => vec![
                workspace_need.clone(),
                m::exact_need(owner, m::endpoint_shared_role(), endpoint_signer),
            ],
        };

        // ---- step 3: park or validate (per arm; same arm order as step 2) ----
        // If any payload is missing, return early with the needs as a park output.
        // Otherwise, run every rule for the matched arm. needs[0] is workspace
        // on both arms; the workspace check itself is shared (see below).
        let park = needs_output(&needs);
        let Some(workspace_payload) = context.payload_for(&needs[0]) else { return Ok(park) };

        match authority {
            InviteAuthority::UserSigned { workspace_id, user_authority, user_invite } => {
                let (Some(user_payload), Some(user_invite_payload)) =
                    (context.payload_for(&needs[1]), context.payload_for(&needs[2]))
                else {
                    return Ok(park);
                };
                check_workspace(workspace_payload, workspace_id)?;

                // The envelope itself must claim to be signed by the named user.
                if envelope.signer_id != user_authority {
                    return Err("user-signed device_invite authority must match signer user".into());
                }
                // user payload: id, envelope shape, key match, workspace match.
                if user_payload.id != user_authority {
                    return Err("device_invite user context payload id mismatch".into());
                }
                let user_envelope = signed_fact::layout::decode_signed_fact(&user_payload.bytes)
                    .map_err(|_| "device_invite signer must be user or endpoint_shared".to_string())?;
                if user_envelope.inner_type != user_layout::TYPE_USER {
                    return Err("device_invite signer must be user or endpoint_shared".into());
                }
                let user = user_layout::decode_fact(&user_envelope.payload)
                    .map_err(|_| "device_invite user signer payload is invalid".to_string())?;
                if envelope.signer_public_key != user.public_key {
                    return Err("device_invite signer public key does not match user".into());
                }
                if user.workspace_id != workspace_id {
                    return Err("device_invite user authority belongs to a different workspace".into());
                }
                // user_invite payload: chains to user, id, envelope shape, workspace, key.
                if user_envelope.signer_id != user_invite {
                    return Err("device_invite user_invite dependency does not match signed user".into());
                }
                if user_invite_payload.id != user_invite {
                    return Err("device_invite user_invite context payload id mismatch".into());
                }
                let ui_envelope = signed_fact::layout::decode_signed_fact(&user_invite_payload.bytes)
                    .map_err(|_| "device_invite user_invite context is not a user_invite fact".to_string())?;
                if ui_envelope.inner_type != user_invite_layout::TYPE_USER_INVITE {
                    return Err("device_invite user_invite dependency is not a user_invite".into());
                }
                let ui = user_invite_layout::decode_fact(&ui_envelope.payload)
                    .map_err(|_| "device_invite user_invite context is not a user_invite fact".to_string())?;
                if ui.workspace_id != workspace_id {
                    return Err("device_invite user_invite belongs to a different workspace".into());
                }
                if ui.public_key != user_envelope.signer_public_key {
                    return Err("device_invite user_invite key does not match user".into());
                }
            }

            InviteAuthority::EndpointSigned { workspace_id, user_authority, endpoint_signer } => {
                let Some(endpoint_payload) = context.payload_for(&needs[1]) else {
                    return Ok(park);
                };
                check_workspace(workspace_payload, workspace_id)?;

                // endpoint_shared payload: id, envelope shape, key match, workspace, user authority.
                if endpoint_payload.id != endpoint_signer {
                    return Err("device_invite endpoint_shared context payload id mismatch".into());
                }
                let ep_envelope = signed_fact::layout::decode_signed_fact(&endpoint_payload.bytes)
                    .map_err(|_| "device_invite signer must be user or endpoint_shared".to_string())?;
                if ep_envelope.inner_type != endpoint_shared_layout::TYPE_ENDPOINT_SHARED {
                    return Err("device_invite signer must be user or endpoint_shared".into());
                }
                let endpoint = endpoint_shared_layout::decode_fact(&ep_envelope.payload)
                    .map_err(|_| "device_invite endpoint_shared signer payload is invalid".to_string())?;
                if envelope.signer_public_key != endpoint.signing_public_key {
                    return Err(
                        "device_invite signer public key does not match endpoint_shared signing key".into(),
                    );
                }
                if endpoint.workspace_id != workspace_id {
                    return Err("endpoint_shared-signed device_invite workspace does not match signer".into());
                }
                if endpoint.user_authority_event_id != user_authority {
                    return Err("endpoint_shared-signed device_invite user authority does not match signer".into());
                }
            }
        }

        // ---- step 4: emit the row + the two offers ----
        Ok(park
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

// =============================================================================
// The two helpers `project()` leans on. Each is short and named precisely.
// =============================================================================

/// Open the signed envelope, confirm it carries a device_invite, decode the
/// inner fact, reject obviously-empty required fields. Pure shape check; no
/// authority logic lives here.
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

/// Both paths require the workspace context payload to match by id and decode
/// as a workspace. Same two checks, same two error strings.
fn check_workspace(payload: &Fact, expected_id: FactId) -> Result<(), String> {
    if payload.id != expected_id {
        return Err("device_invite workspace context payload id mismatch".into());
    }
    workspace_layout::decode_fact(&payload.bytes)
        .map(drop)
        .map_err(|_| "device_invite workspace dependency is not a workspace".into())
}

fn needs_output(needs: &[ContextNeed]) -> ProjectionOutput {
    needs
        .iter()
        .cloned()
        .fold(ProjectionOutput::new(), ProjectionOutput::need)
}

// =============================================================================
// Tests
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
