//! Context matcher contract.

use crate::core::context::{ContextNeed, ContextOffer, ContextSetDelta, Role};
use crate::core::facts::FactId;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContextMatch {
    pub need_owner: FactId,
    pub offer_owner: FactId,
    pub payload_ref: FactId,
}

pub trait ContextMatcher {
    fn role(&self) -> &Role;

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
}
