//! Protocol-neutral command authoring primitives.
//!
//! User-facing commands may query the database directly and read an injected
//! command clock. Commands return authored facts plus a typed receipt; runtime
//! submission is the only path that retains those facts and wakes projection.

use crate::core::facts::{Fact, FactId};

/// Fact id of a workspace in protocol-owned identity data.
pub type WorkspaceId = FactId;

/// A signing capability value returned by protocol-owned auth queries.
///
/// Commands query this before authoring workspace-scoped facts. They do not
/// pick the signer, generate the private key, or mint a new one when no
/// capability exists. Absent capability is an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSigningCapability {
    pub workspace_id: WorkspaceId,
    pub signer_id: FactId,
    pub public_key: crate::core::crypto::Ed25519PublicKey,
    pub private_key: crate::core::crypto::Ed25519PrivateKey,
}

/// An encryption capability value returned by protocol-owned auth queries.
///
/// As with signing, a command may use the secret to seal payloads but must not
/// derive, persist, or rotate it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEncryptionCapability {
    pub workspace_id: WorkspaceId,
    pub frontier_id: FactId,
    pub owner_endpoint_id: FactId,
    pub created_at_ms: u64,
    pub key_secret: crate::core::crypto::XChaCha20Poly1305Key,
}

/// The clock surface a command is allowed to read.
///
/// A command must produce a deterministic next timestamp; it is not allowed to
/// read system time directly. The host plugs in the clock implementation.
pub trait CommandClock {
    fn next_timestamp(&self) -> u64;
}

/// A `CommandClock` backed by a `Fn` closure, used by tests.
pub struct FnClock<F: Fn() -> u64>(pub F);

impl<F: Fn() -> u64> CommandClock for FnClock<F> {
    fn next_timestamp(&self) -> u64 {
        (self.0)()
    }
}

/// A user-facing command's authored output.
///
/// Commands return zero or more authored facts plus a typed receipt. The receipt
/// is intentionally limited to ids, scope ids, and deterministic timestamps that
/// later commands can chain from. Display data comes from `queries.rs` after the
/// runtime has processed the output.
///
/// This bundle is deliberately narrower than `RuntimeEffects`: commands cannot
/// emit row mutations, purges, durable intents, local intents, handler callbacks,
/// worker handles, or registry references. Runtime submission turns these facts
/// into retained pending facts atomically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoredFacts<T> {
    pub receipt: T,
    pub facts: Vec<Fact>,
}

impl<T> AuthoredFacts<T> {
    pub fn new(receipt: T) -> Self {
        Self {
            receipt,
            facts: Vec::new(),
        }
    }

    pub fn with_facts(mut self, facts: Vec<Fact>) -> Self {
        self.facts = facts;
        self
    }

    pub fn into_parts(self) -> (T, Vec<Fact>) {
        (self.receipt, self.facts)
    }
}
