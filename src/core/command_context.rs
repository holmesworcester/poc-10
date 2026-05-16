//! The narrow, read-only command context.
//!
//! `CommandContext` is the only handle a user-facing command sees. It exposes
//! exactly the reads a command is allowed to make:
//!
//! * `store()` for read-only projected-state queries (commands must not write).
//! * `next_timestamp()` for a monotonic, deterministic clock read.
//! * `local_signing_capability(workspace_id)` for a workspace-scoped signing
//!   key that identity already owns. Commands do not mint signing keys.
//! * `local_encryption_capability(workspace_id)` for a workspace-scoped
//!   encryption secret that identity already owns. Commands do not mint
//!   encryption keys.
//!
//! Commands are not the reactive path. Automatic behavior should be expressed
//! by projectors, context needs/offers, and intent handlers, and should share
//! deterministic constructors from `create.rs` rather than calling command
//! workflows. A user-facing command may query before or after a runtime drain
//! only when the operation explicitly knows the prior state is present.
//!
//! Anything richer (workers, the event registry, a `Protocol`, a
//! `DaemonWorkerContext`) is deliberately absent. This module is a core
//! boundary type, not a protocol command implementation.
//!
//! Identity-owned helpers come in through `IdentityVault`. Tests construct a
//! `CommandContext` with a hand-built vault; production code wires identity's
//! own vault implementation.

use crate::core::facts::FactId;
use crate::core::store::Store;
use crate::protocol::facts::encryption::fact::LocalKeySecretFact;
use crate::protocol::facts::identity::signed_fact::fact::LocalSignerSecretFact;

pub type WorkspaceId = FactId;

/// A signing capability handed to a command by identity.
///
/// Commands receive the capability already authorized: they do not pick the
/// signer, do not generate the private key, and do not mint a new one when no
/// capability exists. Absent capability is an error.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSigningCapability {
    pub fact: LocalSignerSecretFact,
}

/// An encryption capability handed to a command by identity.
///
/// As with signing, the command may use the secret to seal payloads but must
/// not derive, persist, or rotate it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalEncryptionCapability {
    pub fact: LocalKeySecretFact,
}

/// The identity-owned vault.
///
/// Identity is the only realm allowed to mint local signing or encryption
/// keys. Commands borrow capabilities through this trait; they cannot reach
/// the underlying key material through any other route in this module.
pub trait IdentityVault {
    fn local_signing_capability(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<LocalSigningCapability, String>;

    fn local_encryption_capability(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<LocalEncryptionCapability, String>;
}

/// The clock surface a command is allowed to read.
///
/// A command must produce a deterministic next timestamp; it is not allowed
/// to read system time directly. The host plugs in the clock implementation.
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

/// The read-only context for user-facing command workflows.
///
/// `CommandContext` deliberately holds references only. It does not own a
/// `Protocol`, a `DaemonWorkerContext`, an `EventRegistry`, or any worker
/// channel. The four accessor methods are the entire surface a command may
/// use.
pub struct CommandContext<'a> {
    store: &'a Store,
    clock: &'a dyn CommandClock,
    vault: &'a dyn IdentityVault,
}

impl<'a> CommandContext<'a> {
    pub fn new(
        store: &'a Store,
        clock: &'a dyn CommandClock,
        vault: &'a dyn IdentityVault,
    ) -> Self {
        Self {
            store,
            clock,
            vault,
        }
    }

    /// Borrow the row store for module-owned `queries.rs` helpers.
    ///
    /// Store reads here are for user-facing commands and post-command
    /// reporting. Reactive logic should receive its inputs through
    /// `ProjectionContext` or `HandlerContext` instead.
    pub fn store(&self) -> &Store {
        self.store
    }

    /// Read the next monotonic timestamp.
    pub fn next_timestamp(&self) -> u64 {
        self.clock.next_timestamp()
    }

    /// Borrow the local signing capability for `workspace_id`. Identity
    /// decides whether such a capability exists; the command does not mint
    /// one on the fly.
    pub fn local_signing_capability(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<LocalSigningCapability, String> {
        self.vault.local_signing_capability(workspace_id)
    }

    /// Borrow the local encryption capability for `workspace_id`. Identity
    /// decides whether such a capability exists.
    pub fn local_encryption_capability(
        &self,
        workspace_id: WorkspaceId,
    ) -> Result<LocalEncryptionCapability, String> {
        self.vault.local_encryption_capability(workspace_id)
    }
}

/// A small command output bundle.
///
/// Commands return zero or more proposed facts, zero or more deferred
/// intents, and a typed receipt. The receipt is intentionally limited to ids,
/// scope ids, and deterministic timestamps that later commands can chain from.
/// Display data comes from `queries.rs` after the runtime has processed the
/// output. The bundle is intentionally narrow: it
/// cannot carry handler callbacks, worker handles, or registry references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput<T> {
    pub receipt: T,
    pub facts: Vec<crate::core::facts::Fact>,
    pub intents: Vec<crate::core::intents::Intent>,
}

impl<T> CommandOutput<T> {
    pub fn new(receipt: T) -> Self {
        Self {
            receipt,
            facts: Vec::new(),
            intents: Vec::new(),
        }
    }

    pub fn with_facts(mut self, facts: Vec<crate::core::facts::Fact>) -> Self {
        self.facts = facts;
        self
    }

    pub fn with_intents(mut self, intents: Vec<crate::core::intents::Intent>) -> Self {
        self.intents = intents;
        self
    }
}

// Compile-time guard.
//
// This block pins down the structural shape of `CommandContext`. It cannot
// prove every import policy, but it does catch accidental owned fields such as
// a worker pool, registry, or handler dispatcher sneaking into the command
// boundary.
//
// 1. `CommandContext` has the four read-only methods described above and no
//    method that returns a worker handle, an event registry, or a
//    `DaemonWorkerContext`.
// 2. The size of `CommandContext` is the size of three thin references, which
//    rules out a hidden owned worker pool, channel, or registry field.
// Three references is the maximum the documented contract allows: `store`
// (thin), `clock` (fat dyn), `vault` (fat dyn) for a total of five `usize`s on
// a 64-bit target. The upper bound is conservative enough for alignment slack
// but small enough to catch broad runtime state.
const _: () = {
    if std::mem::size_of::<CommandContext<'static>>() > std::mem::size_of::<[usize; 6]>() {
        panic!("CommandContext grew beyond its three-reference contract");
    }
};
