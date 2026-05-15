//! Context matcher contract.

use crate::core::context::{ContextNeed, ContextOffer, Role};
use crate::core::facts::FactId;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextMatch {
    pub need_owner: FactId,
    pub offer_owner: FactId,
    pub payload_ref: FactId,
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
