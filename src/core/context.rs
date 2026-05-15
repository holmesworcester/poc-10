//! Context needs and offers used to wake projection.

use crate::core::facts::{FactId, FactScope};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Role(String);

impl Role {
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
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextNeed {
    pub owner: FactId,
    pub role: Role,
    pub scope: FactScope,
    pub selector: Selector,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextOffer {
    pub owner: FactId,
    pub role: Role,
    pub scope: FactScope,
    pub selector: Selector,
    pub payload_ref: FactId,
}

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
        self.needs.sort();
        self.needs.dedup();
        self.offers.sort();
        self.offers.dedup();
        self
    }
}

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
