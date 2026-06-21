//! Verus proof obligations for the `protocol::auth::signature` fact family.
//!
//! No theorem in this file currently claims threat-model coverage. The previous
//! standalone protocol fact model was removed because it proved only a
//! parallel model, not `SignatureProjector` over the Rust `Fact`,
//! `ProjectionContext`, and `ProjectionOutput` values we execute.
//!
//! The first real theorem for this module must be over the actual
//! `SignatureProjector::project` path or over a verified view extracted from
//! its actual Rust inputs and output. Its safety direction should prove:
//!
//! ```text
//! successful signature projection emits a `signature_proof` offer
//!   -> the input fact authenticated with Ed25519 over
//!      signature_message(workspace_id, target_fact_id)
//!      and the emitted offer key is exactly
//!      ContextKeyPart::bytes(target_fact_id)
//!      || ContextKeyPart::bytes(signer_public_key)
//!      and the sync-share contribution carries no authority context
//! ```
//!
//! Crypto binding may be consumed from `src/core/proofs.rs`, but workspace,
//! target, and signer relationships belong in this module's Rust-backed proof.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;
