//! Context matcher contract.

use crate::core::context::{ContextNeed, ContextOffer, ContextSetDelta, Role};
use crate::core::facts::FactId;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextMatch {
    pub need_owner: FactId,
    pub offer_owner: FactId,
}

pub trait ContextMatcher {
    fn role(&self) -> &Role;

    fn match_new_need(
        &self,
        need: &ContextNeed,
        existing_offers: &[ContextOffer],
    ) -> Vec<ContextMatch>;

    fn match_new_offer(
        &self,
        offer: &ContextOffer,
        existing_needs: &[ContextNeed],
    ) -> Vec<ContextMatch>;
}

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
}

pub fn exact_selector_match(need: &ContextNeed, offer: &ContextOffer) -> Option<ContextMatch> {
    if need.role == offer.role && need.scope == offer.scope && need.selector == offer.selector {
        Some(ContextMatch {
            need_owner: need.owner,
            offer_owner: offer.owner,
        })
    } else {
        None
    }
}

pub fn match_context_delta(
    delta: &ContextSetDelta,
    available_needs: &[ContextNeed],
    available_offers: &[ContextOffer],
    matchers: &[&dyn ContextMatcher],
) -> Vec<ContextMatch> {
    let mut matches = BTreeSet::new();
    for need in &delta.added_needs {
        for matcher in matchers_for_role(matchers, &need.role) {
            matches.extend(matcher.match_new_need(need, available_offers));
        }
    }
    for offer in &delta.added_offers {
        for matcher in matchers_for_role(matchers, &offer.role) {
            matches.extend(matcher.match_new_offer(offer, available_needs));
        }
    }
    matches.into_iter().collect()
}

fn matchers_for_role<'a>(
    matchers: &'a [&'a dyn ContextMatcher],
    role: &'a Role,
) -> impl Iterator<Item = &'a dyn ContextMatcher> + 'a {
    matchers
        .iter()
        .copied()
        .filter(move |matcher| matcher.role() == role)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{Role, Selector};
    use crate::core::facts::FactScope;

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
        };

        let matched = exact_selector_match(&need, &offer).unwrap();
        assert_eq!(matched.need_owner, [1; 32]);
        assert_eq!(matched.offer_owner, [3; 32]);
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
            },
            ContextOffer {
                owner: [5; 32],
                role,
                scope: FactScope::Local,
                selector: Selector::from_bytes([2; 32]),
            },
        ];

        let matches = matcher.match_new_need(&need, &offers);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].offer_owner, [3; 32]);
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

    #[test]
    fn context_delta_matching_only_wakes_added_relationships() {
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
        let stable_need = ContextNeed {
            owner: [1; 32],
            role: role.clone(),
            scope: FactScope::Global,
            selector: Selector::from_bytes([7; 32]),
        };
        let added_need = ContextNeed {
            owner: [2; 32],
            role: role.clone(),
            scope: FactScope::Global,
            selector: Selector::from_bytes([8; 32]),
        };
        let removed_need = ContextNeed {
            owner: [3; 32],
            role: role.clone(),
            scope: FactScope::Global,
            selector: Selector::from_bytes([9; 32]),
        };
        let available_offer = ContextOffer {
            owner: [4; 32],
            role,
            scope: FactScope::Global,
            selector: Selector::from_bytes([8; 32]),
        };
        let delta = ContextSetDelta {
            added_needs: vec![added_need],
            removed_needs: vec![removed_need],
            added_offers: Vec::new(),
            removed_offers: Vec::new(),
        };

        let matches = match_context_delta(
            &delta,
            &[stable_need],
            &[available_offer],
            &[&matcher as &dyn ContextMatcher],
        );

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].need_owner, [2; 32]);
        assert_eq!(matches[0].offer_owner, [4; 32]);
    }

    #[test]
    fn context_delta_matching_deduplicates_symmetric_new_matches() {
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
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
        };
        let delta = ContextSetDelta {
            added_needs: vec![need.clone()],
            removed_needs: Vec::new(),
            added_offers: vec![offer.clone()],
            removed_offers: Vec::new(),
        };

        let matches = match_context_delta(
            &delta,
            &[need],
            &[offer],
            &[&matcher as &dyn ContextMatcher],
        );

        assert_eq!(
            matches,
            vec![ContextMatch {
                need_owner: [1; 32],
                offer_owner: [3; 32],
            }]
        );
    }
}
