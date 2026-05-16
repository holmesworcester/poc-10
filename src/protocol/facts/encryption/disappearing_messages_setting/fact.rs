//! Disappearing-messages setting fact shape for the poc-10 target tree.
//!
//! A setting fact carries the disappearing-messages TTL the author wishes to
//! impose for a given scope inside the workspace (workspace-wide or a
//! narrower scope such as a single channel/thread, identified by
//! `scope_kind` + `scope_id`). The active setting is the latest admitted
//! setting for a given `(workspace_id, scope_kind, scope_id)` under the
//! deterministic `(created_at_ms, fact_id)` ordering; successive settings
//! reference their predecessor via `supersedes_setting_id` so projection
//! can chain them.
//!
//! Legacy parity gaps (intentional, deferred to later slices) -- see
//! `project.rs` for the runtime equivalent of this list:
//!  - Legacy validates a signed envelope around the payload; the target
//!    `identity::signed_fact` envelope is a separate fact module not yet wired in.
//!  - Legacy resolves an authority-admin dependency and checks the signer
//!    public key against the workspace admin set. The admin module is not
//!    yet ported to the target tree.
//!  - Legacy validates monotonic floor against the predecessor setting's
//!    `expires_at_or_before_minute`. The chain dependency lookup against
//!    sibling encryption events is not available here, so the field is
//!    carried but not cross-checked.

use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type SettingId = FactId;
pub type AuthorUserId = FactId;

/// Scope-kind tag carried in the fact so the projector can key the row by
/// `(workspace_id, scope_kind, scope_id)`. Concrete scope vocabularies are
/// owned by their respective fact modules; the setting only carries the
/// tag plus a 32-byte scope id.
pub const SCOPE_KIND_WORKSPACE: u8 = 0;
pub const SCOPE_KIND_CHANNEL: u8 = 1;
pub const SCOPE_KIND_THREAD: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisappearingMessagesSettingFact {
    pub workspace_id: WorkspaceId,
    /// `Some(id)` names the predecessor setting whose floor this setting
    /// must not regress. `None` (sentinel `[0; 32]` on the wire) is only
    /// legal when no setting has yet been admitted for the scope.
    pub supersedes_setting_id: Option<SettingId>,
    pub ttl_minutes: u32,
    /// Monotonic floor: any message whose authoring unix-minute is `<
    /// retire_minute` is considered retired regardless of its per-message
    /// stamp.
    pub retire_minute: u64,
    /// Scope this setting applies to: `(scope_kind, scope_id)`. For
    /// workspace-wide settings, `scope_kind = SCOPE_KIND_WORKSPACE` and
    /// `scope_id = workspace_id`.
    pub scope_kind: u8,
    pub scope_id: FactId,
    pub author_user_id: AuthorUserId,
    pub created_at_ms: u64,
}
