//! Poc-10 admin grant projector.
//!
//! Validates the admin fact payload and emits a single `PutRow` atomic intent.
//!
//! Legacy parity gap (intentional): the legacy projector required a signed
//! envelope wrapping the admin payload plus workspace, authority-admin, and
//! user dependencies, and enforced cross-fact authority rules:
//!
//! * bootstrap grants: signer == workspace, `user_fact_id == workspace_id`, and
//!   `admin.public_key == workspace.public_key`,
//! * ongoing grants: signer == authority admin id, signer key == authority
//!   admin public key, authority admin belongs to the same workspace, and
//!   `admin.public_key == user.public_key` for the named user.
//!
//! Those checks rely on the not-yet-ported signed envelope verification and
//! dependency lookup plumbing. The poc-10 projection plane does not yet expose
//! signed-envelope-verified dependencies (cf. the same gap in the target
//! identity_user projector), so the target projector currently performs only payload
//! decoding and basic structural validation. The cross-fact authority and
//! signer/key bindings will be tightened once signed_fact verification and
//! dependency context are wired into the projector trait.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::layout;
use super::rows::admin_row;

#[derive(Debug, Clone, Default)]
pub struct AdminProjector;

impl AdminProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for AdminProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let admin = layout::decode_fact(&fact.bytes)?;
        if admin.workspace_id == [0u8; 32] {
            return Err("admin workspace_id must not be zero".to_string());
        }
        if admin.public_key == [0u8; 32] {
            return Err("admin public_key must not be zero".to_string());
        }
        Ok(ProjectionOutput::new()
            .intent(AtomicIntent::PutRow(admin_row(fact.id, &admin)?).into_intent()))
    }
}
