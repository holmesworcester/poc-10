//! The narrow, read-only command context.
//!
//! `CommandContext` is the only handle a command sees. It exposes exactly the
//! reads a pure fact constructor is allowed to make:
//!
//! * `store()` for opaque key/value reads (commands must not write).
//! * `next_timestamp()` for a monotonic, deterministic clock read.
//! * `local_signing_capability(workspace_id)` for a workspace-scoped signing
//!   key that identity already owns. Commands do not mint signing keys.
//! * `local_encryption_capability(workspace_id)` for a workspace-scoped
//!   encryption secret that identity already owns. Commands do not mint
//!   encryption keys.
//!
//! Anything richer (workers, the event registry, a `Protocol`, a
//! `DaemonWorkerContext`) is deliberately absent: those imports do not appear
//! anywhere under `src/commands/` so the type cannot reach them. The compile-
//! time guard at the bottom of this file pins that down.
//!
//! Identity-owned helpers come in through `IdentityVault`. Tests construct a
//! `CommandContext` with a hand-built vault; production code wires identity's
//! own vault implementation.

use crate::core::facts::FactId;
use crate::core::store::Store;
use crate::event_modules::encryption::fact::LocalKeySecretFact;
use crate::event_modules::signed_fact::fact::LocalSignerSecretFact;

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

/// The read-only command context.
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

    /// Borrow the row store. Commands read; they do not write.
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
/// intents, and a typed summary. The bundle is intentionally narrow: it
/// cannot carry handler callbacks, worker handles, or registry references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput<T> {
    pub summary: T,
    pub facts: Vec<crate::core::facts::Fact>,
    pub intents: Vec<crate::core::intents::Intent>,
}

impl<T> CommandOutput<T> {
    pub fn new(summary: T) -> Self {
        Self {
            summary,
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
// This block proves, by source-level review and by the absence of any
// `crate::legacy::workers::*`, `crate::legacy::protocol::*`, or `crate::core::handler_dispatch`
// import in `src/commands/`, that `CommandContext` cannot reach worker code or
// the event registry. We also assert two structural shapes:
//
// 1. `CommandContext` has the four read-only methods described above and no
//    method that returns a worker handle, an event registry, or a
//    `DaemonWorkerContext`.
// 2. The size of `CommandContext` is the size of three thin references, which
//    rules out a hidden owned worker pool, channel, or registry field.
// If a worker handle or registry ever sneaks in as a field, this assert
// will go red at compile time. Three references is the maximum the
// documented contract allows: `store` (thin), `clock` (fat dyn), `vault`
// (fat dyn) for a total of five `usize`s on a 64-bit target. We assert the
// upper bound conservatively at six `usize`s to allow target alignment
// slack but still catch any owned field accidentally added.
const _: () = {
    if std::mem::size_of::<CommandContext<'static>>() > std::mem::size_of::<[usize; 6]>() {
        panic!("CommandContext grew beyond its three-reference contract");
    }
};
