//! Protocol-neutral command authoring primitives.
//!
//! Commands are the system's explicit user/API write path. A command starts from
//! caller intent and the currently projected database state, may query
//! protocol-owned local capabilities, stamps deterministic command time through a
//! `CommandClock`, and returns authored fact bytes plus a receipt. Those facts do
//! not become visible rows immediately; runtime submission retains them and lets
//! ordinary projection publish context, rows, intents, and later visibility.
//!
//! Command implementation still belongs with the protocol fact family that owns
//! the operation. Fact-family `cli.rs` modules parse argv and format display
//! output, `api.rs` modules decide what facts to author, and `author.rs` /
//! `encode.rs` modules build canonical signed or encrypted bytes. Commands may
//! compose several newly authored facts in memory, but they do not write rows,
//! drive projection, dispatch handlers, emit intents directly, or privately
//! drain their own output.
//!
//! This file is the shared core vocabulary for that boundary. It defines the
//! command clock, local capability value types that command code may borrow from
//! protocol-owned state, and `AuthoredFacts`, the narrow receipt-plus-facts bundle
//! accepted by runtime submission. It deliberately does not register command
//! names, parse CLI argv, know protocol layouts, or decide command semantics.

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

// Tests.
// Ordered most-central-first: the authored-facts bundle before the clock helper.
#[cfg(test)]
mod tests {
    use super::{AuthoredFacts, CommandClock, FnClock};
    use crate::core::facts::{Fact, FactScope};

    #[test]
    fn authored_facts_preserves_receipt_and_fact_list() {
        let facts = vec![
            Fact::new(FactScope::Local, 10, b"first command fact".to_vec()),
            Fact::new(FactScope::Local, 11, b"second command fact".to_vec()),
        ];

        let (receipt, emitted) = AuthoredFacts::new("receipt")
            .with_facts(facts.clone())
            .into_parts();

        assert_eq!(receipt, "receipt");
        assert_eq!(emitted, facts);
    }

    #[test]
    fn fn_clock_delegates_to_injected_time_source() {
        let clock = FnClock(|| 123_456u64);

        assert_eq!(clock.next_timestamp(), 123_456);
    }
}
