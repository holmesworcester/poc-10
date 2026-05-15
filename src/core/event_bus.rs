//! Protocol-neutral projection wake loop.
//!
//! This module owns the small cycle that every fact follows:
//!
//! ```text
//! submit fact -> pending projection -> projector output
//!             -> replace standing context
//!             -> context delta matching for new needs/offers
//!             -> wake matched owners
//!             -> collect intent output
//! ```
//!
//! The bus is deliberately below storage in this slice. The row schemas already
//! name durable tables for facts, context, pending projection, and intents; this
//! module first makes the semantics crisp enough to persist without carrying
//! forward the old lifecycle vocabulary.

use crate::core::context::{ContextNeed, ContextOffer, ContextSet, ContextSetDelta};
use crate::core::facts::{Fact, FactId};
use crate::core::intents::Intent;
use crate::core::matchers::{match_context_delta, ContextMatcher};
use crate::core::projection::{run_projection, Projector};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DrainReport {
    pub projections: usize,
    pub context_matches: usize,
    pub wakes: usize,
    pub intents: usize,
}

#[derive(Debug, Default)]
pub struct EventBus {
    facts: BTreeMap<FactId, Fact>,
    context_by_owner: BTreeMap<FactId, ContextSet>,
    pending_projection: VecDeque<FactId>,
    pending_owners: BTreeSet<FactId>,
    intents: Vec<Intent>,
}

impl EventBus {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn submit_fact(&mut self, fact: Fact) -> bool {
        let id = fact.id;
        if self.facts.insert(id, fact).is_some() {
            return false;
        }
        self.wake(id)
    }

    pub fn has_fact(&self, id: &FactId) -> bool {
        self.facts.contains_key(id)
    }

    pub fn context(&self, owner: &FactId) -> Option<&ContextSet> {
        self.context_by_owner.get(owner)
    }

    pub fn pending_len(&self) -> usize {
        self.pending_projection.len()
    }

    pub fn intents(&self) -> &[Intent] {
        &self.intents
    }

    pub fn take_intents(&mut self) -> Vec<Intent> {
        std::mem::take(&mut self.intents)
    }

    pub fn drain(
        &mut self,
        projector: &impl Projector,
        matchers: &[&dyn ContextMatcher],
        limit: usize,
    ) -> Result<DrainReport, String> {
        let mut report = DrainReport::default();
        while report.projections < limit {
            let Some(owner) = self.pop_pending() else {
                break;
            };
            let Some(fact) = self.facts.get(&owner).cloned() else {
                continue;
            };
            let previous = self
                .context_by_owner
                .get(&owner)
                .cloned()
                .unwrap_or_default();
            let offers = self.matching_offers_for_owner(&owner, matchers);
            let run = run_projection(projector, &fact, &previous, offers)?;
            self.replace_context(owner, run.context);
            report.projections += 1;
            report.context_matches +=
                self.wake_context_matches(&run.context_delta, matchers, &mut report);
            report.intents += run.intents.len();
            self.intents.extend(run.intents);
        }
        Ok(report)
    }

    fn wake(&mut self, owner: FactId) -> bool {
        if !self.pending_owners.insert(owner) {
            return false;
        }
        self.pending_projection.push_back(owner);
        true
    }

    fn pop_pending(&mut self) -> Option<FactId> {
        let owner = self.pending_projection.pop_front()?;
        self.pending_owners.remove(&owner);
        Some(owner)
    }

    fn replace_context(&mut self, owner: FactId, context: ContextSet) {
        if context.needs.is_empty() && context.offers.is_empty() {
            self.context_by_owner.remove(&owner);
        } else {
            self.context_by_owner.insert(owner, context);
        }
    }

    fn wake_context_matches(
        &mut self,
        delta: &ContextSetDelta,
        matchers: &[&dyn ContextMatcher],
        report: &mut DrainReport,
    ) -> usize {
        let needs = self.all_needs();
        let offers = self.all_offers();
        let matches = match_context_delta(delta, &needs, &offers, matchers);
        for matched in &matches {
            if self.wake(matched.need_owner) {
                report.wakes += 1;
            }
        }
        matches.len()
    }

    fn matching_offers_for_owner(
        &self,
        owner: &FactId,
        matchers: &[&dyn ContextMatcher],
    ) -> Vec<ContextOffer> {
        let Some(context) = self.context_by_owner.get(owner) else {
            return Vec::new();
        };
        let offers = self.all_offers();
        let delta = ContextSetDelta {
            added_needs: context.needs.clone(),
            removed_needs: Vec::new(),
            added_offers: Vec::new(),
            removed_offers: Vec::new(),
        };
        let matches = match_context_delta(&delta, &[], &offers, matchers)
            .into_iter()
            .map(|matched| (matched.offer_owner, matched.payload_ref))
            .collect::<BTreeSet<_>>();
        offers
            .into_iter()
            .filter(|offer| matches.contains(&(offer.owner, offer.payload_ref)))
            .collect()
    }

    fn all_needs(&self) -> Vec<ContextNeed> {
        self.context_by_owner
            .values()
            .flat_map(|context| context.needs.iter().cloned())
            .collect()
    }

    fn all_offers(&self) -> Vec<ContextOffer> {
        self.context_by_owner
            .values()
            .flat_map(|context| context.offers.iter().cloned())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{Role, Selector};
    use crate::core::facts::FactScope;
    use crate::core::intents::{IntentExecution, IntentKind};
    use crate::core::matchers::ExactSelectorMatcher;
    use crate::core::projection::{ProjectionContext, ProjectionOutput};
    use std::cell::Cell;

    #[test]
    fn standing_need_does_not_create_a_reproject_loop() {
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
        let projector = NeedOfferProjector::new(role, Selector::from_bytes([8; 32]));
        let fact = Fact::new(FactScope::Global, 1, b"need".to_vec());
        let mut bus = EventBus::new();

        assert!(bus.submit_fact(fact.clone()));
        let report = bus
            .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("drain");

        assert_eq!(report.projections, 1);
        assert_eq!(report.wakes, 0);
        assert_eq!(bus.pending_len(), 0);
        assert_eq!(projector.need_projections.get(), 1);
        assert_eq!(bus.context(&fact.id).unwrap().needs.len(), 1);
        assert!(bus.intents().is_empty());
    }

    #[test]
    fn new_offer_wakes_existing_need_owner_once() {
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
        let projector = NeedOfferProjector::new(role, Selector::from_bytes([8; 32]));
        let need = Fact::new(FactScope::Global, 1, b"need".to_vec());
        let offer = Fact::new(FactScope::Global, 2, b"offer".to_vec());
        let mut bus = EventBus::new();

        bus.submit_fact(need.clone());
        bus.drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("need drain");
        bus.submit_fact(offer.clone());
        let report = bus
            .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("offer drain");

        assert_eq!(report.projections, 2);
        assert_eq!(report.context_matches, 1);
        assert_eq!(report.wakes, 1);
        assert_eq!(projector.need_projections.get(), 2);
        assert_eq!(projector.offer_projections.get(), 1);
        assert!(bus.context(&need.id).is_none());
        assert_eq!(bus.intents().len(), 1);
        assert!(!bus.submit_fact(offer));
        let duplicate = bus
            .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("duplicate drain");
        assert_eq!(duplicate.projections, 0);
        assert_eq!(bus.intents().len(), 1);
    }

    #[test]
    fn many_new_offers_do_not_amplify_one_owner_wake() {
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
        let projector = NeedOfferProjector::new(role, Selector::from_bytes([8; 32]));
        let need = Fact::new(FactScope::Global, 1, b"need".to_vec());
        let offer_a = Fact::new(FactScope::Global, 2, b"offer-a".to_vec());
        let offer_b = Fact::new(FactScope::Global, 3, b"offer-b".to_vec());
        let mut bus = EventBus::new();

        bus.submit_fact(need);
        bus.drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("need drain");
        bus.submit_fact(offer_a);
        bus.submit_fact(offer_b);
        let report = bus
            .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("offer drain");

        assert_eq!(report.projections, 3);
        assert_eq!(report.context_matches, 2);
        assert_eq!(report.wakes, 1);
        assert_eq!(bus.pending_len(), 0);
        assert_eq!(bus.intents().len(), 1);
    }

    #[test]
    fn new_need_finds_existing_offer_and_wakes_itself() {
        let role = Role::new("exact").unwrap();
        let matcher = ExactSelectorMatcher::new(role.clone());
        let projector = NeedOfferProjector::new(role, Selector::from_bytes([8; 32]));
        let offer = Fact::new(FactScope::Global, 1, b"offer".to_vec());
        let need = Fact::new(FactScope::Global, 2, b"need".to_vec());
        let mut bus = EventBus::new();

        bus.submit_fact(offer);
        bus.drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("offer drain");
        bus.submit_fact(need);
        let report = bus
            .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
            .expect("need drain");

        assert_eq!(report.projections, 2);
        assert_eq!(report.context_matches, 1);
        assert_eq!(report.wakes, 1);
        assert_eq!(bus.intents().len(), 1);
    }

    struct NeedOfferProjector {
        role: Role,
        selector: Selector,
        need_projections: Cell<usize>,
        offer_projections: Cell<usize>,
    }

    impl NeedOfferProjector {
        fn new(role: Role, selector: Selector) -> Self {
            Self {
                role,
                selector,
                need_projections: Cell::new(0),
                offer_projections: Cell::new(0),
            }
        }
    }

    impl Projector for NeedOfferProjector {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            if fact.bytes.starts_with(b"offer") {
                self.offer_projections.set(self.offer_projections.get() + 1);
                return Ok(ProjectionOutput::new().offer(ContextOffer {
                    owner: fact.id,
                    role: self.role.clone(),
                    scope: fact.scope.clone(),
                    selector: self.selector.clone(),
                    payload_ref: fact.id,
                }));
            }
            self.need_projections.set(self.need_projections.get() + 1);
            if context.offers().is_empty() {
                return Ok(ProjectionOutput::new().need(ContextNeed {
                    owner: fact.id,
                    role: self.role.clone(),
                    scope: fact.scope.clone(),
                    selector: self.selector.clone(),
                }));
            }
            Ok(ProjectionOutput::new().intent(Intent::new(
                IntentKind::new("open_context").unwrap(),
                IntentExecution::Atomic,
                fact.id,
                context.payload_refs().next().unwrap_or(fact.id),
            )))
        }
    }
}
