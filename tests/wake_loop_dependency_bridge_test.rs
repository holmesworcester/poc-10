use std::cell::Cell;
use std::collections::BTreeSet;

use topo::core::facts::{Fact, FactId, FactScope};
use topo::core::matchers::{ContextMatcher, ExactSelectorMatcher};
use topo::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use topo::core::store::Store;
use topo::core::wake_loop::WakeLoop;
use topo::legacy::protocol::event_modules::test_events::event_with_deps::{
    layout, projector, rows, types,
};

fn event_fact(event: types::EventWithDeps) -> Fact {
    let bytes = layout::encode(&event);
    Fact::new(FactScope::Global, event.timestamp, bytes)
}

fn event_with_deps(timestamp: u64, dependencies: Vec<FactId>, payload: u8) -> Fact {
    event_fact(types::EventWithDeps {
        timestamp,
        dependencies,
        payload: [payload; types::PAYLOAD_BYTES],
    })
}

fn staged_event(index: u64, inner_bytes: Vec<u8>) -> Fact {
    Fact::new(
        FactScope::Local,
        0,
        layout::encode_staged(&types::StagedEventWithDeps { index, inner_bytes }),
    )
}

#[test]
fn event_with_deps_bridge_resolves_out_of_order_dependencies_by_context() {
    let projector = projector::Poc10EventWithDepsProjector::new();
    let matcher = ExactSelectorMatcher::new(projector::event_context_role());
    let dep = event_with_deps(1, Vec::new(), 1);
    let child = event_with_deps(2, vec![dep.id], 2);
    let grandchild = event_with_deps(3, vec![child.id], 3);
    let mut bus = WakeLoop::new();

    bus.submit_fact(grandchild.clone());
    bus.submit_fact(child.clone());
    let initial = bus
        .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
        .expect("initial out-of-order drain");
    assert_eq!(initial.projections, 2);
    assert_eq!(initial.wakes, 0);
    assert_eq!(initial.intents, 0);
    assert_eq!(bus.context(&child.id).unwrap().needs.len(), 1);
    assert_eq!(bus.context(&grandchild.id).unwrap().needs.len(), 1);

    bus.submit_fact(dep.clone());
    let resolved = bus
        .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
        .expect("dependency drain");

    assert_eq!(resolved.projections, 3);
    assert_eq!(resolved.wakes, 2);
    assert_eq!(resolved.intents, 0);
    for fact in [&dep, &child, &grandchild] {
        let context = bus.context(&fact.id).expect("standing offer context");
        assert!(context.needs.is_empty());
        assert_eq!(context.offers.len(), 1);
        assert_eq!(context.offers[0].payload_ref, fact.id);
    }
    assert!(bus.intents().is_empty());
    assert!(!bus.submit_fact(dep));
    let duplicate = bus
        .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
        .expect("duplicate drain");
    assert_eq!(duplicate.projections, 0);
    assert!(bus.intents().is_empty());
}

#[test]
fn event_with_deps_bridge_never_exposes_failed_dependency_context() {
    let projector = RejectingEventWithDepsProjector::new();
    let matcher = ExactSelectorMatcher::new(projector::event_context_role());
    let dep = event_with_deps(1, Vec::new(), 1);
    let child = event_with_deps(2, vec![dep.id], 2);
    projector.reject(dep.id);
    let mut bus = WakeLoop::new();

    bus.submit_fact(child.clone());
    bus.submit_fact(dep.clone());
    let err = bus
        .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
        .expect_err("dependency projector rejects first");

    assert!(
        err.contains("event_with_deps bridge rejected dependency"),
        "{err}"
    );
    assert_eq!(bus.pending_len(), 1);
    assert_eq!(projector.materialized.get(), 0);
    let child_context = bus.context(&child.id).expect("child still waiting");
    assert_eq!(child_context.needs.len(), 1);
    assert!(child_context.offers.is_empty());
    assert!(bus.context(&dep.id).is_none());

    projector.allow(dep.id);
    let resolved = bus
        .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
        .expect("retry after dependency is valid");

    assert_eq!(resolved.projections, 2);
    assert_eq!(resolved.wakes, 1);
    assert_eq!(projector.materialized.get(), 2);
    assert!(bus.context(&child.id).unwrap().needs.is_empty());
}

#[test]
fn staged_event_bridge_writes_row_during_atomic_projection_drain() {
    let store = Store::open_memory_with_schemas(rows::SCHEMAS).expect("open staged event schema");
    let inner = event_with_deps(42, vec![[1; 32], [2; 32]], 7);
    let staged = staged_event(17, inner.bytes.clone());
    let mut bus = WakeLoop::new();

    bus.submit_fact(staged);
    let projected = bus
        .drain_applying_atomic_rows(
            &projector::Poc10EventWithDepsProjector::new(),
            &[],
            &store,
            &[rows::STAGED_EVENTS_WITH_DEPS],
            10,
        )
        .expect("project staged event");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());
    assert_eq!(
        store
            .table_rows(rows::STAGED_EVENTS_WITH_DEPS)
            .expect("staged rows"),
        vec![(17u64.to_be_bytes().to_vec(), inner.bytes)]
    );
}

struct RejectingEventWithDepsProjector {
    rejected: std::cell::RefCell<BTreeSet<FactId>>,
    materialized: Cell<usize>,
}

impl RejectingEventWithDepsProjector {
    fn new() -> Self {
        Self {
            rejected: std::cell::RefCell::new(BTreeSet::new()),
            materialized: Cell::new(0),
        }
    }

    fn reject(&self, id: FactId) {
        self.rejected.borrow_mut().insert(id);
    }

    fn allow(&self, id: FactId) {
        self.rejected.borrow_mut().remove(&id);
    }
}

impl Projector for RejectingEventWithDepsProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        if self.rejected.borrow().contains(&fact.id) {
            return Err("event_with_deps bridge rejected dependency".to_string());
        }

        let output = projector::Poc10EventWithDepsProjector::new().project(fact, context)?;
        if output.needs.is_empty() && !output.offers.is_empty() {
            self.materialized.set(self.materialized.get() + 1);
        }
        Ok(output)
    }
}
