//! Device-invite projector with the bootstrap-vs-delegated split lifted into a
//! typed variant.
//!
//! The baseline encodes "who signed this invite?" as the presence/absence of
//! `user_invite_event_id: Option<FactId>`. That is an in-band signal: a reader
//! must remember the convention to decode it.
//!
//! Here we classify the invite into `InviteAuthority` up front, then drive
//! the rest of `project()` from one `match`. Each arm carries exactly the
//! fact ids it needs, and runs its own checks inline. There is no shared
//! helper that takes a boolean flag.
//!
//! `InviteAuthority` is `pub`: it advertises the contract to any reader of
//! the module and lets tests pattern-match on the path directly.

use crate::core::context::ContextNeed;
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use crate::event_modules::identity_device_invite::fact::DeviceInviteFact;
use crate::event_modules::identity_device_invite::layout;
use crate::event_modules::identity_device_invite::rows::device_invite_row;
use crate::event_modules::identity_endpoint_shared::layout as endpoint_shared_layout;
use crate::event_modules::identity_matchers as im;
use crate::event_modules::identity_user::layout as user_layout;
use crate::event_modules::identity_user_invite::layout as user_invite_layout;
use crate::event_modules::identity_workspace::layout as workspace_layout;
use crate::event_modules::signed_fact;

/// Which party signed a device_invite envelope. Derived from the decoded fact
/// plus the envelope's `signer_id`. Each variant carries exactly the fact ids
/// the matching validation path needs.
#[derive(Debug, Clone, Copy)]
pub enum InviteAuthority {
    /// Signed by the user themselves. We must also load the `user_invite`
    /// that originally admitted them, because user-signed invites preserve
    /// that ancestry.
    UserSigned { user_authority: FactId, user_invite: FactId },
    /// Signed by an already-admitted endpoint acting on behalf of the user.
    EndpointSigned { user_authority: FactId, signer_endpoint: FactId },
}

impl InviteAuthority {
    pub fn classify(invite: &DeviceInviteFact, signer_id: FactId) -> Self {
        match invite.user_invite_event_id {
            Some(user_invite) => Self::UserSigned {
                user_authority: invite.user_authority_event_id,
                user_invite,
            },
            None => Self::EndpointSigned {
                user_authority: invite.user_authority_event_id,
                signer_endpoint: signer_id,
            },
        }
    }
}

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
        // 1. Envelope-level checks.
        if fact.scope != FactScope::Global {
            return Err("device_invite fact must have global scope".to_string());
        }
        let envelope = signed_fact::layout::decode_signed_fact(&fact.bytes)
            .map_err(|_| "device_invite fact must be signed".to_string())?;
        if envelope.inner_type != layout::TYPE_DEVICE_INVITE {
            return Err("signed fact does not contain a device_invite".to_string());
        }

        // 2. Inner payload structural checks.
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

        // 3. Classify, then declare needs per arm. Workspace is shared.
        let owner = fact.id;
        let authority = InviteAuthority::classify(&invite, envelope.signer_id);
        let workspace_need = im::exact_need(owner, im::workspace_role(), invite.workspace_id);
        let needs: Vec<ContextNeed> = match authority {
            InviteAuthority::UserSigned { user_authority, user_invite } => vec![
                workspace_need.clone(),
                im::exact_need(owner, im::user_role(), user_authority),
                im::exact_need(owner, im::user_invite_role(), user_invite),
            ],
            InviteAuthority::EndpointSigned { signer_endpoint, .. } => vec![
                workspace_need.clone(),
                im::exact_need(owner, im::endpoint_shared_role(), signer_endpoint),
            ],
        };

        // 4. Park (re-emit needs) if any are unfilled.
        let mut output = ProjectionOutput::new();
        for need in &needs {
            output = output.need(need.clone());
        }
        if needs.iter().any(|n| context.payload_for(n).is_none()) {
            return Ok(output);
        }

        // 5. Workspace check is identical on both paths.
        let workspace_fact = context.payload_for(&workspace_need).expect("filled");
        if workspace_fact.id != invite.workspace_id {
            return Err("device_invite workspace context payload id mismatch".to_string());
        }
        workspace_layout::decode_fact(&workspace_fact.bytes)
            .map_err(|_| "device_invite workspace dependency is not a workspace".to_string())?;

        // 6. Authority validation: each arm sees only what it needs.
        match authority {
            InviteAuthority::UserSigned { user_authority, user_invite } => {
                // The envelope itself must be signed by the named user.
                if envelope.signer_id != user_authority {
                    return Err("user-signed device_invite authority must match signer user".to_string());
                }
                // Load and decode the user fact.
                let user_fact = context.payload_for(&needs[1]).expect("filled");
                if user_fact.id != user_authority {
                    return Err("device_invite user context payload id mismatch".to_string());
                }
                let user_env = signed_fact::layout::decode_signed_fact(&user_fact.bytes)
                    .map_err(|_| "device_invite signer must be user or endpoint_shared".to_string())?;
                if user_env.inner_type != user_layout::TYPE_USER {
                    return Err("device_invite signer must be user or endpoint_shared".to_string());
                }
                let user = user_layout::decode_fact(&user_env.payload)
                    .map_err(|_| "device_invite user signer payload is invalid".to_string())?;
                // Signing key must equal the user's published key.
                if envelope.signer_public_key != user.public_key {
                    return Err("device_invite signer public key does not match user".to_string());
                }
                // The user must live in the same workspace as the invite.
                if user.workspace_id != invite.workspace_id {
                    return Err("device_invite user authority belongs to a different workspace".to_string());
                }
                // The user envelope must have been signed by the named user_invite.
                if user_env.signer_id != user_invite {
                    return Err("device_invite user_invite dependency does not match signed user".to_string());
                }
                // Load and decode the user_invite fact.
                let invite_fact = context.payload_for(&needs[2]).expect("filled");
                if invite_fact.id != user_invite {
                    return Err("device_invite user_invite context payload id mismatch".to_string());
                }
                let inv_env = signed_fact::layout::decode_signed_fact(&invite_fact.bytes)
                    .map_err(|_| "device_invite user_invite context is not a user_invite fact".to_string())?;
                if inv_env.inner_type != user_invite_layout::TYPE_USER_INVITE {
                    return Err("device_invite user_invite dependency is not a user_invite".to_string());
                }
                let ui = user_invite_layout::decode_fact(&inv_env.payload)
                    .map_err(|_| "device_invite user_invite context is not a user_invite fact".to_string())?;
                if ui.workspace_id != invite.workspace_id {
                    return Err("device_invite user_invite belongs to a different workspace".to_string());
                }
                if ui.public_key != user_env.signer_public_key {
                    return Err("device_invite user_invite key does not match user".to_string());
                }
            }

            InviteAuthority::EndpointSigned { user_authority, signer_endpoint } => {
                // Load and decode the endpoint_shared fact.
                let endpoint_fact = context.payload_for(&needs[1]).expect("filled");
                if endpoint_fact.id != signer_endpoint {
                    return Err("device_invite endpoint_shared context payload id mismatch".to_string());
                }
                let ep_env = signed_fact::layout::decode_signed_fact(&endpoint_fact.bytes)
                    .map_err(|_| "device_invite signer must be user or endpoint_shared".to_string())?;
                if ep_env.inner_type != endpoint_shared_layout::TYPE_ENDPOINT_SHARED {
                    return Err("device_invite signer must be user or endpoint_shared".to_string());
                }
                let endpoint = endpoint_shared_layout::decode_fact(&ep_env.payload)
                    .map_err(|_| "device_invite endpoint_shared signer payload is invalid".to_string())?;
                // Signing key must equal the endpoint's published signing key.
                if envelope.signer_public_key != endpoint.signing_public_key {
                    return Err("device_invite signer public key does not match endpoint_shared signing key".to_string());
                }
                // Workspaces and user authorities must agree.
                if endpoint.workspace_id != invite.workspace_id {
                    return Err("endpoint_shared-signed device_invite workspace does not match signer".to_string());
                }
                if endpoint.user_authority_event_id != user_authority {
                    return Err("endpoint_shared-signed device_invite user authority does not match signer".to_string());
                }
            }
        }

        // 7. Materialize the row and the two offers.
        Ok(output
            .intent(AtomicIntent::PutRow(device_invite_row(fact.id, &invite)?).into_intent())
            .offer(im::exact_offer(fact.id, im::device_invite_role()))
            .offer(im::scoped_key_offer(
                fact.id,
                im::device_invite_key_role(),
                invite.workspace_id,
                im::device_invite_key(invite.user_authority_event_id, invite.public_key),
            )))
    }
}
