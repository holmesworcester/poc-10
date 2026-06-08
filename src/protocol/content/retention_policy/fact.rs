//! Disappearing-messages retention policy fact shape for the poc-10 target tree.
//!
//! A retention policy fact carries the disappearing-messages TTL the author
//! wishes to impose for a given scope inside the workspace (workspace-wide or a
//! narrower scope such as a single channel/thread, identified by `scope_kind` +
//! `scope_id`). The active policy is the latest admitted policy for a given
//! `(workspace_id, scope_kind, scope_id)` under the deterministic
//! `(created_at_ms, fact_id)` ordering; successive policies reference their
//! predecessor via `supersedes_policy_id` so projection can chain them.
//!
//! Current boundaries:
//! - Natural signature verification is owned by this fact layout and projector.
//! - Workspace-admin authority is validated by the projector context.
//! - Monotonic floor checks are enforced through the supersedes chain in the
//!   retention policy projector.

use crate::core::crypto::Ed25519PublicKey;
use crate::core::facts::FactId;

pub type WorkspaceId = FactId;
pub type PolicyId = FactId;
pub type AuthorUserId = FactId;
pub type SignerId = FactId;

/// Scope-kind tag carried in the fact so the projector can key the row by
/// `(workspace_id, scope_kind, scope_id)`. Concrete scope vocabularies are
/// owned by their respective fact modules; the policy only carries the
/// tag plus a 32-byte scope id.
pub const SCOPE_KIND_WORKSPACE: u8 = 0;
pub const SCOPE_KIND_CHANNEL: u8 = 1;
pub const SCOPE_KIND_THREAD: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionPolicyFact {
    pub workspace_id: WorkspaceId,
    /// `Some(id)` names the predecessor policy whose floor this policy
    /// must not regress. `None` (sentinel `[0; 32]` on the wire) is only
    /// legal when no policy has yet been admitted for the scope.
    pub supersedes_policy_id: Option<PolicyId>,
    pub ttl_minutes: u32,
    /// Monotonic floor: any message whose authoring unix-minute is `<
    /// retire_minute` is considered retired regardless of its per-message
    /// stamp.
    pub retire_minute: u64,
    /// Scope this policy applies to: `(scope_kind, scope_id)`. For
    /// workspace-wide policies, `scope_kind = SCOPE_KIND_WORKSPACE` and
    /// `scope_id = workspace_id`.
    pub scope_kind: u8,
    pub scope_id: FactId,
    pub author_user_id: AuthorUserId,
    pub signer_id: SignerId,
    pub signer_public_key: Ed25519PublicKey,
    pub created_at_ms: u64,
}
