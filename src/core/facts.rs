//! Protocol-neutral fact identity and visibility scope.
//!
//! Facts are the immutable inputs to the runtime. Core gives every byte string
//! a content id and records how this store admitted it; projection later turns
//! that byte string into protocol rows, context, time wakes, and follow-up
//! intents. This file deliberately stops before any protocol-specific meaning:
//! a fact tag, signature, message body, key wrap, or sync frame is interpreted
//! only by the protocol module that owns that layout.
//!
//! The id is the BLAKE3 hash of the bytes, so changing scope or timestamp does
//! not change content identity. Scope and timestamp are local admission
//! metadata. They describe how this store may expose the bytes and how pending
//! projection should be ordered; they are not part of the protocol payload.
//!
//! Scope is deliberately small. `Global` can be synced, `Local` is private to
//! the store, and `Scoped` gives a protocol-defined namespace plus id for data
//! that should only move inside that boundary. If a new kind of visibility is
//! needed, change this file and the storage codecs together; do not smuggle it
//! into protocol payload bytes.

/// Content-addressed identity of immutable fact bytes.
pub type FactId = [u8; 32];

/// Protocol vocabulary for scoped facts.
///
/// The lowercase ASCII shape mirrors roles, timelines, and intent kinds: these
/// identifiers are durable protocol names, not display strings.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopeKind(String);

impl ScopeKind {
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty() {
            return Err("scope kind cannot be empty".to_string());
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(format!("invalid scope kind {value:?}"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Local visibility attached to fact bytes at admission time.
///
/// Scope is not part of the hash. The same bytes admitted twice with different
/// scopes still identify the same fact; `fact_store` keeps the first local
/// admission record that made those bytes visible in this store.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FactScope {
    Global,
    Local,
    Scoped { kind: ScopeKind, id: FactId },
}

/// Immutable fact bytes plus the local admission metadata core needs to route them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    /// Content id, equal to `fact_id(bytes)`.
    pub id: FactId,
    /// Local visibility attached when the fact was admitted.
    pub scope: FactScope,
    /// Local admission timestamp used for deterministic ordering.
    pub timestamp: u64,
    /// Immutable protocol-owned payload bytes.
    pub bytes: Vec<u8>,
}

impl Fact {
    /// Construct a fact and derive its id from `bytes`.
    pub fn new(scope: FactScope, timestamp: u64, bytes: Vec<u8>) -> Self {
        let id = fact_id(&bytes);
        Self {
            id,
            scope,
            timestamp,
            bytes,
        }
    }

    /// Return the exact bytes whose hash is `id`.
    pub fn body(&self) -> &[u8] {
        &self.bytes
    }
}

/// Compute the stable content id for fact bytes.
pub fn fact_id(bytes: &[u8]) -> FactId {
    *blake3::hash(bytes).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fact_id_is_deterministic_and_input_sensitive() {
        assert_eq!(fact_id(b"a"), fact_id(b"a"));
        assert_ne!(fact_id(b"a"), fact_id(b"b"));
    }

    #[test]
    fn scope_kind_is_small_stable_vocabulary() {
        assert!(ScopeKind::new("local_1").is_ok());
        assert!(ScopeKind::new("").is_err());
        assert!(ScopeKind::new("Bad").is_err());
        assert!(ScopeKind::new("bad-name").is_err());
    }
}
