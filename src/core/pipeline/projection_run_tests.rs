use super::projection_run::{run_projection_with_context, ProjectionRun};
use crate::core::context::{ContextNeed, ContextOffer, ContextSet, Role, Selector};
use crate::core::facts::{Fact, FactScope};
use crate::core::intents::{Intent, IntentKind};
use crate::core::projectors::{ProjectionContext, ProjectionOutput, Projector, TimeWake, Timeline};

#[test]
fn projection_run_rejects_offer_owned_by_another_fact() {
    let fact = Fact::new(FactScope::Global, 1, b"owned".to_vec());
    let projector = BadOfferOwnerProjector;

    let err = run_projection(&projector, &fact, &ContextSet::new(), Vec::new())
        .expect_err("projection should reject foreign offer owner");

    assert!(err.contains("projector emitted offer with owner"));
}

#[test]
fn projection_run_rejects_need_owned_by_another_fact() {
    let fact = Fact::new(FactScope::Global, 1, b"owned".to_vec());
    let projector = BadNeedOwnerProjector;

    let err = run_projection(&projector, &fact, &ContextSet::new(), Vec::new())
        .expect_err("projection should reject foreign need owner");

    assert!(err.contains("projector emitted need with owner"));
}

#[test]
fn projection_run_rejects_time_wake_owned_by_another_fact() {
    let fact = Fact::new(FactScope::Global, 1, b"owned".to_vec());
    let projector = BadTimeWakeOwnerProjector;

    let err = run_projection(&projector, &fact, &ContextSet::new(), Vec::new())
        .expect_err("projection should reject foreign time-wake owner");

    assert!(err.contains("projector emitted time wake"));
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

    let first =
        run_projection(&projector, &fact, &ContextSet::new(), Vec::new()).expect("first run");
    assert_eq!(first.context_delta.added_needs.len(), 1);
    assert_eq!(first.context_delta.removed_needs.len(), 0);

    let second = run_projection(&projector, &fact, &first.context, Vec::new()).expect("second run");
    assert!(second.context_delta.is_empty());
    assert_eq!(second.context, first.context);
    assert!(second.pipeline.intents.is_empty());
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
    };

    let next =
        run_projection(&projector, &fact, &previous, vec![offer]).expect("projection with context");

    assert!(next.context.needs.is_empty());
    assert_eq!(next.context_delta.removed_needs, previous.needs);
    assert_eq!(next.context_delta.added_needs.len(), 0);
    assert_eq!(next.pipeline.intents.len(), 1);
    assert_eq!(next.pipeline.intents[0].kind.as_str(), "followup");
}

fn run_projection(
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
                fact.id,
                context
                    .offers()
                    .first()
                    .map(|offer| offer.owner)
                    .unwrap_or(fact.id),
            )))
        }
    }
}

struct BadOfferOwnerProjector;

impl Projector for BadOfferOwnerProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        Ok(ProjectionOutput::new().offer(ContextOffer {
            owner: [9; 32],
            role: Role::new("exact").unwrap(),
            scope: fact.scope.clone(),
            selector: Selector::from_bytes(fact.id),
        }))
    }
}

struct BadNeedOwnerProjector;

impl Projector for BadNeedOwnerProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        Ok(ProjectionOutput::new().need(ContextNeed {
            owner: [9; 32],
            role: Role::new("exact").unwrap(),
            scope: fact.scope.clone(),
            selector: Selector::from_bytes(fact.id),
        }))
    }
}

struct BadTimeWakeOwnerProjector;

impl Projector for BadTimeWakeOwnerProjector {
    fn project(
        &self,
        _fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        Ok(ProjectionOutput::new().time_wake(TimeWake {
            owner: [9; 32],
            timeline: Timeline::new("test").unwrap(),
            at: 1,
        }))
    }
}
