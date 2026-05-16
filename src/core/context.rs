//! Standing context relationships used to wake fact projection.
//!
//! Context is the durable matching surface between projectors; it is not a
//! hidden dependency loader or a second projection queue. A projector writes
//! the needs and offers it owns, and role-specific matchers report newly
//! satisfiable relationships. The semantic meaning of a role or selector stays
//! with the fact module that created it.
//!
//! `scope`, `role`, and `selector` form the match key. `owner` says which fact
//! produced the row so later projection can replace that fact's context without
//! deleting anyone else's rows. `payload_ref` names the fact to load after a
//! match; keeping it separate from `owner` lets wrapper facts advertise inner
//! material without pretending the wrapper and payload have the same id.

use crate::core::facts::{FactId, FactScope};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Role(String);

impl Role {
    /// Roles are protocol identifiers, not free-form labels.
    ///
    /// The lowercase ASCII shape keeps persisted rows stable across languages
    /// and makes accidental UI strings or Rust type names fail early.
    pub fn new(value: impl Into<String>) -> Result<Self, String> {
        let value = value.into();
        if value.is_empty() {
            return Err("context role cannot be empty".to_string());
        }
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
        {
            return Err(format!("invalid context role {value:?}"));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Selector(Vec<u8>);

impl Selector {
    /// Build an opaque selector owned by one fact module.
    ///
    /// Core stores and sorts these bytes, but never parses them. If matching
    /// needs range, prefix, or version semantics, that logic belongs in the
    /// module's `ContextMatcher`, not in this type.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A standing request by one fact for matching context.
///
/// The need's `owner` is the fact that should be woken when a compatible offer
/// appears. A need is not inherently blocking: the owning projector decides on
/// each run whether missing context means "wait", "project a partial result",
/// or "stop needing this context".
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextNeed {
    pub owner: FactId,
    pub role: Role,
    pub scope: FactScope,
    pub selector: Selector,
}

/// A standing statement that one fact can provide context to matching needs.
///
/// The offer's `owner` is the fact that emitted this relationship. `payload_ref`
/// is the fact core should load and pass to the woken projector when this offer
/// matches; it is usually the owner, but can name another fact when a local
/// projection advertises context on behalf of a shared or derived fact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextOffer {
    pub owner: FactId,
    pub role: Role,
    pub scope: FactScope,
    pub selector: Selector,
    pub payload_ref: FactId,
}

/// The complete standing context emitted by a single projection owner.
///
/// Projection output replaces the previous set for that owner. This replacement
/// model is what prevents stable unmet needs from self-waking forever: only
/// added or removed relationships produce a delta for matchers to inspect.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContextSet {
    pub needs: Vec<ContextNeed>,
    pub offers: Vec<ContextOffer>,
}

impl ContextSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn need(mut self, need: ContextNeed) -> Self {
        self.needs.push(need);
        self
    }

    pub fn offer(mut self, offer: ContextOffer) -> Self {
        self.offers.push(offer);
        self
    }

    pub fn normalized(mut self) -> Self {
        // Normalization is deliberately mechanical. It gives the storage layer
        // deterministic deltas without deciding whether any particular context
        // row is semantically redundant.
        self.needs.sort();
        self.needs.dedup();
        self.offers.sort();
        self.offers.dedup();
        self
    }
}

/// The added and removed relationships from replacing one owner's context set.
///
/// Matchers only consider additions for wake generation. Removals are still
/// recorded so tests and persistence can prove that projection replacement is
/// exact.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContextSetDelta {
    pub added_needs: Vec<ContextNeed>,
    pub removed_needs: Vec<ContextNeed>,
    pub added_offers: Vec<ContextOffer>,
    pub removed_offers: Vec<ContextOffer>,
}

impl ContextSetDelta {
    pub fn is_empty(&self) -> bool {
        self.added_needs.is_empty()
            && self.removed_needs.is_empty()
            && self.added_offers.is_empty()
            && self.removed_offers.is_empty()
    }
}

/// Compare relationship sets as durable facts, not queue entries.
///
/// The wake loop uses this after every projection. Re-emitting the same need or
/// offer is a no-op; changing it is represented as removal plus addition so the
/// matcher sees only genuinely new possible matches.
pub fn diff_context_sets(previous: &ContextSet, next: &ContextSet) -> ContextSetDelta {
    let previous_needs = previous.needs.iter().cloned().collect::<BTreeSet<_>>();
    let next_needs = next.needs.iter().cloned().collect::<BTreeSet<_>>();
    let previous_offers = previous.offers.iter().cloned().collect::<BTreeSet<_>>();
    let next_offers = next.offers.iter().cloned().collect::<BTreeSet<_>>();

    ContextSetDelta {
        added_needs: next_needs.difference(&previous_needs).cloned().collect(),
        removed_needs: previous_needs.difference(&next_needs).cloned().collect(),
        added_offers: next_offers.difference(&previous_offers).cloned().collect(),
        removed_offers: previous_offers.difference(&next_offers).cloned().collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::facts::FactScope;

    #[test]
    fn role_rejects_broad_free_text() {
        assert!(Role::new("exact_event").is_ok());
        assert!(Role::new("ExactEvent").is_err());
        assert!(Role::new("exact-event").is_err());
    }

    #[test]
    fn context_set_builder_keeps_needs_and_offers_explicit() {
        let id = [1; 32];
        let role = Role::new("exact").unwrap();
        let selector = Selector::from_bytes([2; 32]);
        let set = ContextSet::new()
            .need(ContextNeed {
                owner: id,
                role: role.clone(),
                scope: FactScope::Global,
                selector: selector.clone(),
            })
            .offer(ContextOffer {
                owner: id,
                role,
                scope: FactScope::Global,
                selector,
                payload_ref: id,
            });

        assert_eq!(set.needs.len(), 1);
        assert_eq!(set.offers.len(), 1);
    }

    #[test]
    fn normalized_context_set_sorts_and_deduplicates() {
        let id = [1; 32];
        let role = Role::new("exact").unwrap();
        let need = ContextNeed {
            owner: id,
            role,
            scope: FactScope::Global,
            selector: Selector::from_bytes([2; 32]),
        };

        let set = ContextSet::new()
            .need(need.clone())
            .need(need.clone())
            .normalized();

        assert_eq!(set.needs, vec![need]);
    }

    #[test]
    fn diff_context_sets_reports_only_real_replacements() {
        let id = [1; 32];
        let role = Role::new("exact").unwrap();
        let stable = ContextNeed {
            owner: id,
            role: role.clone(),
            scope: FactScope::Global,
            selector: Selector::from_bytes([2; 32]),
        };
        let added = ContextNeed {
            owner: id,
            role,
            scope: FactScope::Global,
            selector: Selector::from_bytes([3; 32]),
        };

        let previous = ContextSet::new()
            .need(stable.clone())
            .need(stable.clone())
            .normalized();
        let next = ContextSet::new()
            .need(stable)
            .need(added.clone())
            .normalized();
        let delta = diff_context_sets(&previous, &next);

        assert_eq!(delta.added_needs, vec![added]);
        assert!(delta.removed_needs.is_empty());
        assert!(delta.added_offers.is_empty());
        assert!(delta.removed_offers.is_empty());
    }

    #[test]
    fn identical_context_sets_have_empty_delta() {
        let id = [1; 32];
        let role = Role::new("exact").unwrap();
        let selector = Selector::from_bytes([2; 32]);
        let set = ContextSet::new()
            .need(ContextNeed {
                owner: id,
                role: role.clone(),
                scope: FactScope::Global,
                selector: selector.clone(),
            })
            .offer(ContextOffer {
                owner: id,
                role,
                scope: FactScope::Global,
                selector,
                payload_ref: id,
            })
            .normalized();

        assert!(diff_context_sets(&set, &set).is_empty());
    }
}
