//! Disappearing-messages setting projector (poc-10 target tree).
//!
//! Decodes a setting fact and emits a single `PutRow` into
//! `disappearing_messages_setting_rows` keyed by
//! `(workspace_id, scope_kind, scope_id, setting_id)`.
//!
//! Legacy parity gaps (intentional; skipped because the sibling encryption
//! modules they reach into are parked under `src/event_modules/encryption/`
//! pending a split-by-fact-family refactor on another branch):
//!  - Signed envelope decode and signer/admin public-key checks. The target
//!    `signed_fact` module and `identity_admin` module are not surfaced
//!    inside this projector yet.
//!  - Authority-admin chain validation that the signer is an admin event
//!    for the named workspace. The admin event module is not ported into
//!    the target `event_modules/` directory at this slice.
//!  - Monotonic floor cross-check against the `supersedes_setting_id`
//!    predecessor's `retire_minute`. The predecessor lookup needs cross-
//!    fact dependency resolution that the target `ProjectionContext` does
//!    not expose today; the field is carried but not validated against the
//!    chain. (Local well-formedness — `supersedes_setting_id` is `None` iff
//!    it decodes to the all-zero sentinel — is still enforced by the
//!    layout.)
//!  - Bootstrap-from-workspace admission path (initial setting signed by
//!    the workspace event itself). With the signed envelope skipped, the
//!    distinction collapses to a layout-level decode and is reapplied once
//!    the signed envelope module lands.

use crate::core::facts::Fact;
use crate::core::intents::AtomicIntent;
use crate::core::projection::{ProjectionContext, ProjectionOutput, Projector};

use super::layout;
use super::rows::setting_row;

#[derive(Debug, Clone, Default)]
pub struct DisappearingMessagesSettingProjector;

impl DisappearingMessagesSettingProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for DisappearingMessagesSettingProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let setting = layout::decode_fact(&fact.bytes)?;
        if setting.ttl_minutes == 0 {
            return Err("disappearing setting ttl_minutes must be non-zero".to_string());
        }
        if setting.created_at_ms == 0 {
            return Err("disappearing setting created_at_ms must be non-zero".to_string());
        }
        if setting.scope_kind == super::fact::SCOPE_KIND_WORKSPACE
            && setting.scope_id != setting.workspace_id
        {
            return Err(
                "disappearing setting workspace-scope id must match workspace_id".to_string(),
            );
        }
        let row = setting_row(fact.id, &setting)?;
        Ok(ProjectionOutput::new().intent(AtomicIntent::PutRow(row).into_intent()))
    }
}
