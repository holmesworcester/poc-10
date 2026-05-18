//! Projector contract for fact plus context to needs, offers, and intents.

use crate::core::context::{
    diff_context_sets, ContextNeed, ContextOffer, ContextSet, ContextSetDelta,
};
use crate::core::facts::{Fact, FactId};
use crate::core::intents::Intent;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectionContext {
    offers: Vec<ContextOffer>,
    matched: Vec<MatchedContext>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedContext {
    pub need: ContextNeed,
    pub offer: ContextOffer,
    pub payload: Fact,
}

impl ProjectionContext {
    pub fn new(offers: Vec<ContextOffer>) -> Self {
        Self {
            offers,
            matched: Vec::new(),
        }
    }

    pub fn from_matches(matched: Vec<MatchedContext>) -> Self {
        let mut offers = matched
            .iter()
            .map(|matched| matched.offer.clone())
            .collect::<Vec<_>>();
        offers.sort();
        offers.dedup();
        Self { offers, matched }
    }

    pub fn offers(&self) -> &[ContextOffer] {
        &self.offers
    }

    pub fn matched_context(&self) -> &[MatchedContext] {
        &self.matched
    }

    /// Return the payload fact supplied for an exact need, if any.
    ///
    /// This is a lookup over context core already matched and loaded before
    /// projection. It does not query storage or run matcher logic.
    pub fn payload_for(&self, need: &ContextNeed) -> Option<&Fact> {
        self.matched
            .iter()
            .find(|matched| matched.need == *need)
            .map(|matched| &matched.payload)
    }

    pub fn payload_for_checked(
        &self,
        need: &ContextNeed,
        label: &str,
    ) -> Result<Option<&Fact>, String> {
        let Some(matched) = self.matched.iter().find(|matched| matched.need == *need) else {
            return Ok(None);
        };
        if matched.offer.payload_ref != matched.payload.id {
            return Err(format!("{label} context offer payload mismatch"));
        }
        Ok(Some(&matched.payload))
    }

    pub fn matched_payloads_for<'a>(
        &'a self,
        need: &'a ContextNeed,
    ) -> impl Iterator<Item = (&'a ContextOffer, &'a Fact)> + 'a {
        self.matched
            .iter()
            .filter(move |matched| matched.need == *need)
            .map(|matched| (&matched.offer, &matched.payload))
    }

    pub fn offer_payload_refs_matching<'a>(
        &'a self,
        role: &'a crate::core::context::Role,
        scope: &'a crate::core::facts::FactScope,
        selector: &'a crate::core::context::Selector,
    ) -> impl Iterator<Item = FactId> + 'a {
        self.offers
            .iter()
            .filter(move |offer| {
                offer.role == *role && offer.scope == *scope && offer.selector == *selector
            })
            .map(|offer| offer.payload_ref)
    }

    pub fn payload_refs(&self) -> impl Iterator<Item = FactId> + '_ {
        self.offers.iter().map(|offer| offer.payload_ref)
    }

    pub fn payload_facts(&self) -> impl Iterator<Item = &Fact> + '_ {
        self.matched.iter().map(|matched| &matched.payload)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectionOutput {
    pub needs: Vec<ContextNeed>,
    pub offers: Vec<ContextOffer>,
    pub intents: Vec<Intent>,
}

impl ProjectionOutput {
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

    pub fn intent(mut self, intent: Intent) -> Self {
        self.intents.push(intent);
        self
    }

    pub fn context_set(&self) -> ContextSet {
        ContextSet {
            needs: self.needs.clone(),
            offers: self.offers.clone(),
        }
        .normalized()
    }
}

pub trait Projector {
    fn project(&self, fact: &Fact, context: &ProjectionContext)
        -> Result<ProjectionOutput, String>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionRun {
    pub context: ContextSet,
    pub context_delta: ContextSetDelta,
    pub intents: Vec<Intent>,
}

pub fn run_projection(
    projector: &impl Projector,
    fact: &Fact,
    previous_context: &ContextSet,
    offers: Vec<ContextOffer>,
) -> Result<ProjectionRun, String> {
    run_projection_with_context(
        projector,
        fact,
        previous_context,
        ProjectionContext::new(offers),
    )
}

pub fn run_projection_with_context(
    projector: &impl Projector,
    fact: &Fact,
    previous_context: &ContextSet,
    context: ProjectionContext,
) -> Result<ProjectionRun, String> {
    let output = projector.project(fact, &context)?;
    let context = output.context_set();
    let context_delta = diff_context_sets(previous_context, &context);
    Ok(ProjectionRun {
        context,
        context_delta,
        intents: output.intents,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::context::{Role, Selector};
    use crate::core::facts::FactScope;
    use crate::core::intents::{IntentExecution, IntentKind};

    #[test]
    fn projection_output_keeps_context_and_work_separate() {
        let id = [1; 32];
        let role = Role::new("exact").unwrap();
        let selector = Selector::from_bytes([2; 32]);
        let output = ProjectionOutput::new()
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

        assert_eq!(output.needs.len(), 1);
        assert_eq!(output.offers.len(), 1);
        assert!(output.intents.is_empty());
    }

    #[test]
    fn projection_output_exposes_normalized_replacement_context() {
        let id = [1; 32];
        let role = Role::new("exact").unwrap();
        let need = ContextNeed {
            owner: id,
            role,
            scope: FactScope::Global,
            selector: Selector::from_bytes([2; 32]),
        };
        let output = ProjectionOutput::new()
            .need(need.clone())
            .need(need.clone());

        assert_eq!(output.context_set().needs, vec![need]);
    }

    #[test]
    fn projection_run_diffs_standing_context_without_self_waking() {
        let fact = Fact::new(FactScope::Global, 1, b"stable".to_vec());
        let role = Role::new("exact").unwrap();
        let selector = Selector::from_bytes([9; 32]);
        let projector = NeedUntilOffer {
            role,
            selector,
            intent_kind: IntentKind::new("followup").unwrap(),
        };

        let first = run_projection(&projector, &fact, &ContextSet::new(), Vec::new())
            .expect("first projection");
        assert_eq!(first.context_delta.added_needs.len(), 1);
        assert_eq!(first.context_delta.removed_needs.len(), 0);

        let second = run_projection(&projector, &fact, &first.context, Vec::new())
            .expect("second projection");
        assert!(second.context_delta.is_empty());
        assert_eq!(second.context, first.context);
        assert!(second.intents.is_empty());
    }

    #[test]
    fn projection_run_replaces_need_with_intent_when_context_appears() {
        let fact = Fact::new(FactScope::Global, 1, b"recoverable".to_vec());
        let role = Role::new("exact").unwrap();
        let selector = Selector::from_bytes([9; 32]);
        let projector = NeedUntilOffer {
            role: role.clone(),
            selector: selector.clone(),
            intent_kind: IntentKind::new("followup").unwrap(),
        };
        let previous = run_projection(&projector, &fact, &ContextSet::new(), Vec::new())
            .expect("previous projection")
            .context;
        let offer = ContextOffer {
            owner: [2; 32],
            role,
            scope: FactScope::Global,
            selector,
            payload_ref: [3; 32],
        };

        let next = run_projection(&projector, &fact, &previous, vec![offer])
            .expect("projection with context");

        assert!(next.context.needs.is_empty());
        assert_eq!(next.context_delta.removed_needs, previous.needs);
        assert_eq!(next.context_delta.added_needs.len(), 0);
        assert_eq!(next.intents.len(), 1);
        assert_eq!(next.intents[0].kind.as_str(), "followup");
    }

    struct NeedUntilOffer {
        role: Role,
        selector: Selector,
        intent_kind: IntentKind,
    }

    impl Projector for NeedUntilOffer {
        fn project(
            &self,
            fact: &Fact,
            context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            if context.offers().is_empty() {
                Ok(ProjectionOutput::new().need(ContextNeed {
                    owner: fact.id,
                    role: self.role.clone(),
                    scope: fact.scope.clone(),
                    selector: self.selector.clone(),
                }))
            } else {
                Ok(ProjectionOutput::new().intent(Intent::new(
                    self.intent_kind.clone(),
                    IntentExecution::Atomic,
                    fact.id,
                    context.payload_refs().next().unwrap_or(fact.id),
                )))
            }
        }
    }
}
