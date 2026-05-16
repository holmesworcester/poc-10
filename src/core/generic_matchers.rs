//! Generic context matchers.
//!
//! These matchers understand only core context fields. Protocol-specific
//! selector encodings and validation stay in protocol matcher modules.

use crate::core::context::{ContextNeed, ContextOffer, ContextSetDelta, Role, Selector};
use crate::core::facts::FactScope;
use crate::core::matchers::{ContextMatch, ContextMatcher};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactSelectorMatcher {
    role: Role,
}

impl ExactSelectorMatcher {
    pub fn new(role: Role) -> Self {
        Self { role }
    }
}

impl ContextMatcher for ExactSelectorMatcher {
    fn role(&self) -> &Role {
        &self.role
    }

    fn exact_selector_role(&self) -> Option<&Role> {
        Some(&self.role)
    }

    fn match_new_need(
        &self,
        need: &ContextNeed,
        existing_offers: &[ContextOffer],
    ) -> Vec<ContextMatch> {
        if need.role != self.role {
            return Vec::new();
        }
        existing_offers
            .iter()
            .filter_map(|offer| exact_selector_match(need, offer))
            .collect()
    }

    fn match_new_offer(
        &self,
        offer: &ContextOffer,
        existing_needs: &[ContextNeed],
    ) -> Vec<ContextMatch> {
        if offer.role != self.role {
            return Vec::new();
        }
        existing_needs
            .iter()
            .filter_map(|need| exact_selector_match(need, offer))
            .collect()
    }

    fn match_delta(
        &self,
        delta: &ContextSetDelta,
        available_needs: &[ContextNeed],
        available_offers: &[ContextOffer],
    ) -> Vec<ContextMatch> {
        type ExactKey = (FactScope, Selector);

        let mut matches = BTreeSet::new();
        if delta.added_needs.iter().any(|need| need.role == self.role) {
            let mut offers_by_key = BTreeMap::<ExactKey, Vec<&ContextOffer>>::new();
            for offer in available_offers
                .iter()
                .filter(|offer| offer.role == self.role)
            {
                offers_by_key
                    .entry((offer.scope.clone(), offer.selector.clone()))
                    .or_default()
                    .push(offer);
            }
            for need in delta
                .added_needs
                .iter()
                .filter(|need| need.role == self.role)
            {
                if let Some(offers) =
                    offers_by_key.get(&(need.scope.clone(), need.selector.clone()))
                {
                    for offer in offers {
                        matches.insert(ContextMatch {
                            need_owner: need.owner,
                            offer_owner: offer.owner,
                            payload_ref: offer.payload_ref,
                        });
                    }
                }
            }
        }

        if delta
            .added_offers
            .iter()
            .any(|offer| offer.role == self.role)
        {
            let mut needs_by_key = BTreeMap::<ExactKey, Vec<&ContextNeed>>::new();
            for need in available_needs.iter().filter(|need| need.role == self.role) {
                needs_by_key
                    .entry((need.scope.clone(), need.selector.clone()))
                    .or_default()
                    .push(need);
            }
            for offer in delta
                .added_offers
                .iter()
                .filter(|offer| offer.role == self.role)
            {
                if let Some(needs) =
                    needs_by_key.get(&(offer.scope.clone(), offer.selector.clone()))
                {
                    for need in needs {
                        matches.insert(ContextMatch {
                            need_owner: need.owner,
                            offer_owner: offer.owner,
                            payload_ref: offer.payload_ref,
                        });
                    }
                }
            }
        }

        matches.into_iter().collect()
    }
}

pub fn exact_selector_match(need: &ContextNeed, offer: &ContextOffer) -> Option<ContextMatch> {
    if need.role == offer.role && need.scope == offer.scope && need.selector == offer.selector {
        Some(ContextMatch {
            need_owner: need.owner,
            offer_owner: offer.owner,
            payload_ref: offer.payload_ref,
        })
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_selector_match_requires_role_scope_and_selector() {
        let role = Role::new("exact").unwrap();
        let need = ContextNeed {
            owner: [1; 32],
            role: role.clone(),
            scope: FactScope::Global,
            selector: Selector::from_bytes([2; 32]),
        };
        let offer = ContextOffer {
            owner: [3; 32],
            role,
            scope: FactScope::Global,
            selector: Selector::from_bytes([2; 32]),
            payload_ref: [4; 32],
        };

        let matched = exact_selector_match(&need, &offer).unwrap();
        assert_eq!(matched.need_owner, [1; 32]);
        assert_eq!(matched.offer_owner, [3; 32]);
        assert_eq!(matched.payload_ref, [4; 32]);
    }

    #[test]
    fn exact_selector_matcher_finds_new_need_matches() {
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
        let need = ContextNeed {
            owner: [1; 32],
            role: role.clone(),
            scope: FactScope::Global,
            selector: Selector::from_bytes([2; 32]),
        };
        let offers = vec![
            ContextOffer {
                owner: [3; 32],
                role: role.clone(),
                scope: FactScope::Global,
                selector: Selector::from_bytes([2; 32]),
                payload_ref: [4; 32],
            },
            ContextOffer {
                owner: [5; 32],
                role,
                scope: FactScope::Local,
                selector: Selector::from_bytes([2; 32]),
                payload_ref: [6; 32],
            },
        ];

        let matches = matcher.match_new_need(&need, &offers);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].payload_ref, [4; 32]);
    }

    #[test]
    fn exact_selector_matcher_finds_new_offer_matches() {
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
        let offer = ContextOffer {
            owner: [3; 32],
            role: role.clone(),
            scope: FactScope::Global,
            selector: Selector::from_bytes([2; 32]),
            payload_ref: [4; 32],
        };
        let needs = vec![ContextNeed {
            owner: [1; 32],
            role,
            scope: FactScope::Global,
            selector: Selector::from_bytes([2; 32]),
        }];

        let matches = matcher.match_new_offer(&offer, &needs);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].need_owner, [1; 32]);
    }
}
