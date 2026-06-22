//! Verus proof obligations for the `protocol::auth::workspace` fact family.
//!
//! No theorem in this file currently claims threat-model coverage. The previous
//! standalone workspace materialization proof was removed because it proved only
//! a parallel model, not `WorkspaceProjector` over the Rust `Fact`,
//! `ProjectionContext`, and `ProjectionOutput` values we execute.
//!
//! The first real theorem for this module must be over the actual
//! `WorkspaceProjector::project` path and the Rust `Fact`, `ProjectionContext`,
//! and `ProjectionOutput` values it executes. Its safety direction should prove:
//!
//! ```text
//! successful workspace projection materializes a workspace row,
//! auth_workspace offer, or sync-share contribution
//!   -> the input fact is global-scoped and authenticated by verify_fact_id,
//!      signature_proof_ready accepted the exact signature need for
//!      (workspace fact id, workspace fact id, workspace public key),
//!      payload_for_checked accepted the exact workspace_accepted_need,
//!      the accepted payload decodes as invite_accepted for this workspace id,
//!      the emitted row and auth_workspace offer are keyed to the workspace fact,
//!      and the sync-share context_have set includes the signature proof context
//!      but not the local invite_accepted context
//! ```
//!
//! Missing-context branches also need real proofs. They should use core
//! missing-context theorem stubs only for actual `ProjectionContext::payload_for`
//! absence and actual `ProjectionOutput::new().need(...)` parked output shape;
//! the protocol proof still has to prove the emitted needs are the right
//! signature and invite-accepted needs for the workspace fact.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;
