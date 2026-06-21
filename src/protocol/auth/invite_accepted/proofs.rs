//! Verus proof obligations for the `protocol::auth::invite_accepted` fact
//! family.
//!
//! No theorem in this file currently claims threat-model coverage. The previous
//! standalone protocol fact model was removed because it proved only a parallel
//! model, not `InviteAcceptedProjector` over the Rust `Fact`,
//! `ProjectionContext`, and `ProjectionOutput` values we execute.
//!
//! The first real theorem for this module must be over the actual
//! `InviteAcceptedProjector::project` path or over a verified view extracted
//! from its actual Rust inputs and output. Its safety direction should prove:
//!
//! ```text
//! successful invite-accepted projection emits `auth_workspace_accepted`
//!   -> the input fact is local-scoped,
//!      the decoded accepted fact is identity-scoped,
//!      the emitted offer owner is the accepted fact id,
//!      the emitted offer role is AUTH_WORKSPACE_ACCEPTED_ROLE,
//!      and the emitted offer range is exactly the accepted workspace id
//! ```
//!
//! A non-identity-scoped acceptance may still emit connection bootstrap
//! context, but it must not emit accepted-workspace context.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;
