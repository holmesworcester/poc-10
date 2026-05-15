//! Poc-10 device-invite projector.
//!
//! Validates the device-invite fact payload and emits a single `PutRow` atomic
//! intent.
//!
//! Legacy parity gap (intentional, see commit message): the legacy projector
//! unwraps a `signed` envelope and verifies the signer is either the user
//! identity named by the invite (`identity::user` signed with the matching
//! `user_invite` material) or an existing `endpoint_shared` row for the same
//! workspace/user authority. None of `identity_signed`, `identity_user_invite`
//! signing, or `identity_endpoint_shared` are wired into the target tree yet,
//! so the target projector accepts the raw fact body and trusts its declared
//! workspace/user-authority/user-invite fields. The legacy
//! `SendBootstrapRequest` intent emitted by the invite triplet is also
//! deferred; the bootstrap intent will be wired when transit handlers land.
//! This will be tightened once the sibling modules and signed-fact integration
//! land.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

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
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
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
        Ok(ProjectionOutput::new().intent(
            AtomicIntent::PutRow(device_invite_row(fact.id, &device_invite)?).into_intent(),
        ))
    }
}
