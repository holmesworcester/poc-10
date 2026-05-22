//! Standing context relationships used to wake fact projection.
//!
//! Context is the durable matching surface between projectors; it is not a
//! hidden dependency loader or a second projection queue. A projector writes
//! the needs and offers it owns, and core reports newly satisfiable byte-range
//! overlaps. The semantic meaning of a role or key range stays with the fact
//! module that created it.
//!
//! Context is how one fact says "wake me when another fact matching this shape
//! exists" without reaching directly into another module's tables. A need names
//! the fact that should be reprojected. An offer names the fact that can be
//! loaded as matched payload. Core stores both as durable rows and matches them
//! by role, scope, and overlapping opaque byte ranges.
//!
//! `scope`, `role`, `start_key`, and `end_key` form the match surface. `owner`
//! says which fact produced the row so later projection can replace that fact's
//! context without deleting anyone else's rows; the same fact is loaded as the
//! payload when the offer matches a need.
//!
//! Projection owns context by replacement, not append. When a fact projects, it
//! emits the complete current set of needs and offers for that fact. Core diffs
//! that set against the previous durable set, wakes only genuinely new matches,
//! and avoids self-waking loops when stable unmet needs are re-emitted.

use crate::core::facts::{FactId, FactScope};
use crate::core::wire::Writer;
use std::collections::BTreeSet;

/// Protocol-defined relationship role used for context matching.
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

/// Opaque byte key within a context role and scope.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Selector(Vec<u8>);

impl Selector {
    /// Build an opaque range endpoint owned by one fact module.
    ///
    /// Core stores, sorts, and compares these bytes, but never parses them.
    /// Protocol code chooses a canonical byte layout and validates the matched
    /// payload before giving the match any semantic authority.
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
    /// Fact to wake when a compatible offer appears.
    pub owner: FactId,
    /// Matching role.
    pub role: Role,
    /// Matching scope.
    pub scope: FactScope,
    /// Inclusive start of the opaque byte range this need asks for.
    pub start_key: Selector,
    /// Inclusive end of the opaque byte range this need asks for.
    pub end_key: Selector,
}

/// A standing statement that one fact can provide context to matching needs.
///
/// The offer's `owner` is the fact that emitted this relationship and the fact
/// core should load and pass to the woken projector when this offer matches.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextOffer {
    /// Fact that emitted the offer and provides the payload.
    pub owner: FactId,
    /// Matching role.
    pub role: Role,
    /// Matching scope.
    pub scope: FactScope,
    /// Inclusive start of the opaque byte range this offer provides.
    pub start_key: Selector,
    /// Inclusive end of the opaque byte range this offer provides.
    pub end_key: Selector,
}

/// Encode a fact scope into the stable bytes used by context match indexes.
pub(crate) fn scope_key(scope: &FactScope) -> Vec<u8> {
    let mut out = Writer::new();
    encode_scope(&mut out, scope);
    out.finish()
}

/// The complete standing context emitted by a single projection owner.
///
/// Projection output replaces the previous set for that owner. This replacement
/// model is what prevents stable unmet needs from self-waking forever: only
/// added or removed relationships produce a delta for matchers to inspect.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ContextSet {
    /// Standing needs owned by one fact.
    pub needs: Vec<ContextNeed>,
    /// Standing offers owned by one fact.
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
    /// Needs newly visible after replacement.
    pub added_needs: Vec<ContextNeed>,
    /// Needs removed by replacement.
    pub removed_needs: Vec<ContextNeed>,
    /// Offers newly visible after replacement.
    pub added_offers: Vec<ContextOffer>,
    /// Offers removed by replacement.
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
/// Projection commit uses this after every projection. Re-emitting the same
/// need or offer is a no-op; changing it is represented as removal plus
/// addition so the matcher sees only genuinely new possible matches.
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

fn encode_scope(out: &mut Writer, scope: &FactScope) {
    match scope {
        FactScope::Global => out.u8(0),
        FactScope::Local => out.u8(1),
        FactScope::Scoped { kind, id } => {
            out.u8(2);
            out.string_u16be(kind.as_str())
                .expect("scope kind fits u16");
            out.fixed(id);
        }
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
                start_key: selector.clone(),
                end_key: selector.clone(),
            })
            .offer(ContextOffer {
                owner: id,
                role,
                scope: FactScope::Global,
                start_key: selector.clone(),
                end_key: selector,
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
            start_key: Selector::from_bytes([2; 32]),
            end_key: Selector::from_bytes([2; 32]),
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
            start_key: Selector::from_bytes([2; 32]),
            end_key: Selector::from_bytes([2; 32]),
        };
        let added = ContextNeed {
            owner: id,
            role,
            scope: FactScope::Global,
            start_key: Selector::from_bytes([3; 32]),
            end_key: Selector::from_bytes([3; 32]),
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
                start_key: selector.clone(),
                end_key: selector.clone(),
            })
            .offer(ContextOffer {
                owner: id,
                role,
                scope: FactScope::Global,
                start_key: selector.clone(),
                end_key: selector,
            })
            .normalized();

        assert!(diff_context_sets(&set, &set).is_empty());
    }
}
