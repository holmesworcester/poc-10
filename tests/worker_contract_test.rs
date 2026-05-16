use std::cell::{Cell, RefCell};

use topo::core::context::{ContextNeed, ContextOffer, Role, Selector};
use topo::core::facts::{Fact, FactId, FactScope};
use topo::core::handler_dispatch::{HandlerContext, HandlerOutput, IntentHandler};
use topo::core::intents::{Intent, IntentExecution, IntentKind};
use topo::core::matchers::{ContextMatcher, ExactSelectorMatcher};
use topo::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use topo::core::wake_loop::WakeLoop;

#[test]
fn target_admission_tracks_fact_ids_and_drains_local_batch_directly() {
    let facts = vec![fact("batch-a", 1), fact("batch-b", 2), fact("batch-c", 3)];
    let proposed_ids = facts.iter().map(|fact| fact.id).collect::<Vec<_>>();
    let mut bus = WakeLoop::new();

    for fact in facts {
        assert!(bus.submit_fact(fact.clone()));
        assert!(bus.has_fact(&fact.id));
    }

    let projector = CountingProjector::default();
    let report = bus.drain(&projector, &[], 10).expect("drain batch");

    assert_eq!(report.projections, proposed_ids.len());
    assert_eq!(report.wakes, 0);
    assert_eq!(report.intents, 0);
    assert_eq!(bus.pending_len(), 0);
    assert_eq!(projector.projected.borrow().as_slice(), proposed_ids);

    let duplicate = fact("batch-a", 1);
    assert!(!bus.submit_fact(duplicate));
    let duplicate_report = bus
        .drain(&projector, &[], 10)
        .expect("duplicate fact has no work");
    assert_eq!(duplicate_report.projections, 0);
}

#[test]
fn target_drain_limit_applies_only_one_pending_projection_batch() {
    let mut bus = WakeLoop::new();
    bus.submit_fact(fact("limit-a", 1));
    bus.submit_fact(fact("limit-b", 2));
    let projector = CountingProjector::default();

    let first = bus.drain(&projector, &[], 1).expect("first limited drain");
    assert_eq!(first.projections, 1);
    assert_eq!(bus.pending_len(), 1);
    assert_eq!(projector.projected.borrow().len(), 1);

    let second = bus.drain(&projector, &[], 1).expect("second limited drain");
    assert_eq!(second.projections, 1);
    assert_eq!(bus.pending_len(), 0);
    assert_eq!(projector.projected.borrow().len(), 2);
}

#[test]
fn target_wake_loop_fetches_dependency_payload_before_reprojection() {
    let role = role("dependency");
    let matcher = ExactSelectorMatcher::new(role.clone());
    let dep = fact("dependency-source", 1);
    let child = fact("dependency-child", 2);
    let projector = DependencyProjector::new(role, dep.id, child.id);
    let mut bus = WakeLoop::new();

    bus.submit_fact(child.clone());
    let waiting = bus
        .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
        .expect("child waits for dependency");
    assert_eq!(waiting.projections, 1);
    assert_eq!(waiting.wakes, 0);
    assert_eq!(bus.context(&child.id).unwrap().needs.len(), 1);
    assert!(projector.child_payloads.borrow().is_empty());

    bus.submit_fact(dep.clone());
    let resolved = bus
        .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
        .expect("dependency wakes child");

    assert_eq!(resolved.projections, 2);
    assert_eq!(resolved.wakes, 1);
    assert_eq!(projector.child_projections.get(), 2);
    assert_eq!(
        projector.child_payloads.borrow().as_slice(),
        &[dep.bytes.clone()]
    );
    assert!(bus.context(&child.id).is_none());
    assert_eq!(bus.intents().len(), 1);
    assert_eq!(bus.intents()[0].payload, dep.bytes);
}

#[test]
fn target_update_context_reprojects_applied_and_waiting_dependents() {
    let base_role = role("base_dep");
    let update_role = role("update_dep");
    let base_matcher = ExactSelectorMatcher::new(base_role.clone());
    let update_matcher = ExactSelectorMatcher::new(update_role.clone());
    let dep = fact("update-base-dep", 1);
    let child = fact("update-child", 2);
    let blocked = fact("update-blocked-target", 3);
    let updater = fact("update-signal", 4);
    let missing_primary = [88; 32];
    let projector = UpdateProjector::new(
        base_role,
        update_role,
        dep.id,
        child.id,
        blocked.id,
        missing_primary,
        updater.id,
    );
    let matchers = [
        &base_matcher as &dyn ContextMatcher,
        &update_matcher as &dyn ContextMatcher,
    ];
    let mut bus = WakeLoop::new();

    bus.submit_fact(child.clone());
    bus.submit_fact(blocked.clone());
    bus.submit_fact(dep);
    let initial = bus
        .drain(&projector, &matchers, 10)
        .expect("base dependency drain");

    assert_eq!(initial.projections, 4);
    assert_eq!(projector.child_projections.get(), 1);
    assert!(!projector.child_saw_update.get());
    assert_eq!(bus.context(&child.id).unwrap().needs.len(), 1);
    assert_eq!(bus.context(&blocked.id).unwrap().needs.len(), 2);

    bus.submit_fact(updater);
    let updated = bus
        .drain(&projector, &matchers, 10)
        .expect("update wakes dependents");

    assert_eq!(updated.projections, 3);
    assert_eq!(updated.wakes, 2);
    assert_eq!(projector.child_projections.get(), 2);
    assert!(projector.child_saw_update.get());
    assert_eq!(projector.blocked_retired.get(), 1);
    assert!(bus.context(&blocked.id).is_none());
    assert!(bus.intents().iter().any(|intent| {
        intent.kind.as_str() == "retire_fact"
            && intent.execution == IntentExecution::Deferred
            && intent.key == blocked.id
    }));
}

#[test]
fn target_failed_projection_never_surfaces_dependency_context_until_retry() {
    let role = role("retry_dep");
    let matcher = ExactSelectorMatcher::new(role.clone());
    let dep = fact("retry-dependency", 1);
    let child = fact("retry-child", 2);
    let projector = DependencyProjector::new(role, dep.id, child.id);
    projector.reject_dependency.set(true);
    let mut bus = WakeLoop::new();

    bus.submit_fact(child.clone());
    bus.submit_fact(dep.clone());
    let err = bus
        .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
        .expect_err("dependency projection fails");

    assert!(
        err.contains("dependency rejected by target projector"),
        "{err}"
    );
    assert_eq!(bus.pending_len(), 1);
    assert_eq!(projector.child_projections.get(), 1);
    assert!(projector.child_payloads.borrow().is_empty());
    assert!(bus.context(&dep.id).is_none());
    assert_eq!(bus.context(&child.id).unwrap().needs.len(), 1);

    projector.reject_dependency.set(false);
    let retry = bus
        .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
        .expect("dependency retry succeeds");

    assert_eq!(retry.projections, 2);
    assert_eq!(retry.wakes, 1);
    assert_eq!(projector.child_payloads.borrow().as_slice(), &[dep.bytes]);
    assert_eq!(bus.pending_len(), 0);
}

#[test]
fn target_deferred_handler_consumes_only_after_exact_fact_context_exists() {
    let fact = fact("handler-input-fact", 7);
    let mut bus = WakeLoop::new();
    bus.submit_intent(echo_fact_intent(fact.id))
        .expect("submit echo intent");

    let err = bus
        .dispatch_deferred_intents_with_fact_context(&EchoFactHandler, 10)
        .expect_err("missing fact keeps intent queued");
    assert!(err.contains("handler context missing fact"), "{err}");
    assert_eq!(bus.intents().len(), 1);

    bus.submit_fact(fact.clone());
    let report = bus
        .dispatch_deferred_intents_with_fact_context(&EchoFactHandler, 10)
        .expect("dispatch with exact fact context");

    assert_eq!(report.handled, 1);
    assert_eq!(report.intents, 1);
    assert_eq!(bus.intents().len(), 1);
    assert_eq!(bus.intents()[0].kind.as_str(), "echoed_fact");
    assert_eq!(bus.intents()[0].payload, fact.bytes);
}

#[derive(Default)]
struct CountingProjector {
    projected: RefCell<Vec<FactId>>,
}

impl Projector for CountingProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        self.projected.borrow_mut().push(fact.id);
        Ok(ProjectionOutput::new())
    }
}

struct DependencyProjector {
    role: Role,
    dep_id: FactId,
    child_id: FactId,
    reject_dependency: Cell<bool>,
    child_projections: Cell<usize>,
    child_payloads: RefCell<Vec<Vec<u8>>>,
}

impl DependencyProjector {
    fn new(role: Role, dep_id: FactId, child_id: FactId) -> Self {
        Self {
            role,
            dep_id,
            child_id,
            reject_dependency: Cell::new(false),
            child_projections: Cell::new(0),
            child_payloads: RefCell::new(Vec::new()),
        }
    }

    fn dependency_need(&self) -> ContextNeed {
        ContextNeed {
            owner: self.child_id,
            role: self.role.clone(),
            scope: FactScope::Global,
            selector: Selector::from_bytes(self.dep_id),
        }
    }
}

impl Projector for DependencyProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if fact.id == self.dep_id {
            if self.reject_dependency.get() {
                return Err("dependency rejected by target projector".to_string());
            }
            return Ok(ProjectionOutput::new().offer(ContextOffer {
                owner: fact.id,
                role: self.role.clone(),
                scope: fact.scope.clone(),
                selector: Selector::from_bytes(fact.id),
                payload_ref: fact.id,
            }));
        }

        if fact.id == self.child_id {
            self.child_projections
                .set(self.child_projections.get().saturating_add(1));
            let need = self.dependency_need();
            if let Some(payload) = context.payload_for(&need) {
                self.child_payloads.borrow_mut().push(payload.bytes.clone());
                return Ok(ProjectionOutput::new().intent(Intent::new(
                    kind("dependency_child_ready"),
                    IntentExecution::Deferred,
                    fact.id,
                    payload.bytes.clone(),
                )));
            }
            return Ok(ProjectionOutput::new().need(need));
        }

        Err("unknown dependency contract fact".to_string())
    }
}

struct UpdateProjector {
    base_role: Role,
    update_role: Role,
    dep_id: FactId,
    child_id: FactId,
    blocked_id: FactId,
    missing_primary_id: FactId,
    updater_id: FactId,
    child_projections: Cell<usize>,
    child_saw_update: Cell<bool>,
    blocked_retired: Cell<usize>,
}

impl UpdateProjector {
    fn new(
        base_role: Role,
        update_role: Role,
        dep_id: FactId,
        child_id: FactId,
        blocked_id: FactId,
        missing_primary_id: FactId,
        updater_id: FactId,
    ) -> Self {
        Self {
            base_role,
            update_role,
            dep_id,
            child_id,
            blocked_id,
            missing_primary_id,
            updater_id,
            child_projections: Cell::new(0),
            child_saw_update: Cell::new(false),
            blocked_retired: Cell::new(0),
        }
    }

    fn base_need(&self, owner: FactId, selector: FactId) -> ContextNeed {
        ContextNeed {
            owner,
            role: self.base_role.clone(),
            scope: FactScope::Global,
            selector: Selector::from_bytes(selector),
        }
    }

    fn update_need(&self, owner: FactId) -> ContextNeed {
        ContextNeed {
            owner,
            role: self.update_role.clone(),
            scope: FactScope::Global,
            selector: Selector::from_bytes(owner),
        }
    }

    fn offer(&self, owner: FactId, role: Role, selector: FactId) -> ContextOffer {
        ContextOffer {
            owner,
            role,
            scope: FactScope::Global,
            selector: Selector::from_bytes(selector),
            payload_ref: owner,
        }
    }
}

impl Projector for UpdateProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if fact.id == self.dep_id {
            return Ok(ProjectionOutput::new().offer(self.offer(
                fact.id,
                self.base_role.clone(),
                self.dep_id,
            )));
        }

        if fact.id == self.updater_id {
            return Ok(ProjectionOutput::new()
                .offer(self.offer(fact.id, self.update_role.clone(), self.child_id))
                .offer(self.offer(fact.id, self.update_role.clone(), self.blocked_id)));
        }

        if fact.id == self.child_id {
            let update_need = self.update_need(self.child_id);
            if context.payload_for(&update_need).is_some() {
                self.child_projections
                    .set(self.child_projections.get().saturating_add(1));
                self.child_saw_update.set(true);
                return Ok(ProjectionOutput::new().need(update_need));
            }

            let base_need = self.base_need(self.child_id, self.dep_id);
            if context.payload_for(&base_need).is_some() {
                self.child_projections
                    .set(self.child_projections.get().saturating_add(1));
                return Ok(ProjectionOutput::new().need(update_need));
            }

            return Ok(ProjectionOutput::new().need(base_need).need(update_need));
        }

        if fact.id == self.blocked_id {
            let update_need = self.update_need(self.blocked_id);
            if context.payload_for(&update_need).is_some() {
                self.blocked_retired
                    .set(self.blocked_retired.get().saturating_add(1));
                return Ok(ProjectionOutput::new().intent(Intent::new(
                    kind("retire_fact"),
                    IntentExecution::Deferred,
                    fact.id,
                    b"retired".to_vec(),
                )));
            }

            return Ok(ProjectionOutput::new()
                .need(self.base_need(self.blocked_id, self.missing_primary_id))
                .need(update_need));
        }

        Err("unknown update contract fact".to_string())
    }
}

struct EchoFactHandler;

impl IntentHandler for EchoFactHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == "echo_fact"
    }

    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<FactId>, String> {
        let id: FactId = intent
            .key
            .as_slice()
            .try_into()
            .map_err(|_| "echo fact intent key must be a fact id".to_string())?;
        Ok(vec![id])
    }

    fn handle(&self, intent: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String> {
        let id: FactId = intent
            .key
            .as_slice()
            .try_into()
            .map_err(|_| "echo fact intent key must be a fact id".to_string())?;
        let fact = context.require_fact(&id)?;
        Ok(HandlerOutput::new().intent(Intent::new(
            kind("echoed_fact"),
            IntentExecution::Deferred,
            id,
            fact.bytes.clone(),
        )))
    }
}

fn echo_fact_intent(id: FactId) -> Intent {
    Intent::new(kind("echo_fact"), IntentExecution::Deferred, id, Vec::new())
}

fn fact(label: &str, timestamp: u64) -> Fact {
    Fact::new(FactScope::Global, timestamp, label.as_bytes().to_vec())
}

fn role(name: &str) -> Role {
    Role::new(name).expect("valid test role")
}

fn kind(name: &str) -> IntentKind {
    IntentKind::new(name).expect("valid test intent kind")
}
