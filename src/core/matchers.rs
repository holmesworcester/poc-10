//! Core context matching.

use crate::core::context::{ContextNeed, ContextOffer, ContextSetDelta, Role, Selector};
use crate::core::facts::{FactId, FactScope};
use crate::core::store::Store;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextMatch {
    pub need_owner: FactId,
    pub offer_owner: FactId,
    pub payload_ref: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextRoleDeclaration {
    pub role: &'static str,
    pub need_selector: &'static [SelectorFieldDeclaration],
    pub offer_selector: &'static [SelectorFieldDeclaration],
    pub matcher: ContextMatcherDeclaration,
}

impl ContextRoleDeclaration {
    pub const fn exact(role: &'static str) -> Self {
        Self {
            role,
            need_selector: &[],
            offer_selector: &[],
            matcher: ContextMatcherDeclaration::ExactSelector,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectorFieldDeclaration {
    pub name: &'static str,
    pub ty: SelectorFieldType,
    pub offset: usize,
    pub len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectorFieldType {
    U8,
    U16,
    U64,
    FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextMatcherDeclaration {
    ExactSelector,
    SelectOnlySql {
        added_need: SelectOnlyMatcherSql,
        added_offer: SelectOnlyMatcherSql,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelectOnlyMatcherSql {
    pub sql: &'static str,
    pub result: SelectOnlyMatcherResult,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SelectOnlyMatcherResult {
    OffersForNeed,
    NeedsForOffer,
}

pub trait ContextMatcher {
    fn role(&self) -> &Role;

    fn declaration(&self) -> Option<ContextRoleDeclaration> {
        None
    }

    fn exact_selector_role(&self) -> Option<&Role> {
        None
    }

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

    fn matching_offers_for_need_from_store(
        &self,
        _store: &Store,
        _need: &ContextNeed,
    ) -> Result<Option<Vec<ContextOffer>>, String> {
        Ok(None)
    }

    fn matching_needs_for_offer_from_store(
        &self,
        _store: &Store,
        _offer: &ContextOffer,
    ) -> Result<Option<Vec<ContextNeed>>, String> {
        Ok(None)
    }

    fn match_delta(
        &self,
        delta: &ContextSetDelta,
        available_needs: &[ContextNeed],
        available_offers: &[ContextOffer],
    ) -> Vec<ContextMatch> {
        let mut matches = Vec::new();
        for need in &delta.added_needs {
            matches.extend(self.match_new_need(need, available_offers));
        }
        for offer in &delta.added_offers {
            matches.extend(self.match_new_offer(offer, available_needs));
        }
        matches
    }
}

pub fn match_context_delta(
    delta: &ContextSetDelta,
    available_needs: &[ContextNeed],
    available_offers: &[ContextOffer],
    matchers: &[&dyn ContextMatcher],
) -> Vec<ContextMatch> {
    let mut matches = BTreeSet::new();
    for matcher in matchers {
        matches.extend(matcher.match_delta(delta, available_needs, available_offers));
    }
    matches.into_iter().collect()
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
    use crate::core::context::{Role, Selector};
    use crate::core::facts::FactScope;

    struct EchoMatcher {
        role: Role,
    }

    impl EchoMatcher {
        fn new(role: Role) -> Self {
            Self { role }
        }
    }

    impl ContextMatcher for EchoMatcher {
        fn role(&self) -> &Role {
            &self.role
        }

        fn match_new_need(
            &self,
            need: &ContextNeed,
            existing_offers: &[ContextOffer],
        ) -> Vec<ContextMatch> {
            existing_offers
                .iter()
                .filter(|offer| offer.role == self.role && need.role == self.role)
                .map(|offer| ContextMatch {
                    need_owner: need.owner,
                    offer_owner: offer.owner,
                    payload_ref: offer.payload_ref,
                })
                .collect()
        }

        fn match_new_offer(
            &self,
            offer: &ContextOffer,
            existing_needs: &[ContextNeed],
        ) -> Vec<ContextMatch> {
            existing_needs
                .iter()
                .filter(|need| need.role == self.role && offer.role == self.role)
                .map(|need| ContextMatch {
                    need_owner: need.owner,
                    offer_owner: offer.owner,
                    payload_ref: offer.payload_ref,
                })
                .collect()
        }
    }

    #[test]
    fn context_delta_matching_only_wakes_added_relationships() {
        let role = Role::new("exact").unwrap();
        let matcher = EchoMatcher::new(role.clone());
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
            payload_ref: [5; 32],
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
        let matcher = EchoMatcher::new(role.clone());
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
                payload_ref: [4; 32],
            }]
        );
    }

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
