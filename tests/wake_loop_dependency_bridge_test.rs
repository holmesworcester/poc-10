use std::cell::Cell;
use std::collections::BTreeSet;

use topo::core::context::{ContextNeed, ContextOffer, Role, Selector};
use topo::core::facts::{Fact, FactId, FactScope};
use topo::core::intents::AtomicIntent;
use topo::core::matchers::ContextMatcher;
use topo::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use topo::core::store::{Schema, Store, TableName, TableRow};
use topo::core::wake_loop::WakeLoop;
use topo::protocol::matchers::ExactSelectorMatcher;

const MAX_DEPS: usize = 10;
const PAYLOAD_BYTES: usize = 16;
const TYPE_EVENT_WITH_DEPS: u8 = 2;
const TYPE_STAGED_EVENT_WITH_DEPS: u8 = 3;
const ENCODED_BYTES: usize = 1 + 8 + 1 + (MAX_DEPS * 32) + PAYLOAD_BYTES;
const STAGED_ENCODED_BYTES: usize = 1 + 8 + ENCODED_BYTES;
const STAGED_EVENTS_WITH_DEPS: TableName = TableName::new("test_events.staged_event_with_deps");
const SCHEMAS: &[Schema] = &[Schema::durable_row_table(
    "test_events.staged_event_with_deps.v1",
    STAGED_EVENTS_WITH_DEPS,
)];

#[derive(Debug, Clone, PartialEq, Eq)]
struct EventWithDeps {
    timestamp: u64,
    dependencies: Vec<FactId>,
    payload: [u8; PAYLOAD_BYTES],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StagedEventWithDeps {
    index: u64,
    inner_bytes: Vec<u8>,
}

fn event_fact(event: EventWithDeps) -> Fact {
    let bytes = encode_event(&event);
    Fact::new(FactScope::Global, event.timestamp, bytes)
}

fn event_with_deps(timestamp: u64, dependencies: Vec<FactId>, payload: u8) -> Fact {
    event_fact(EventWithDeps {
        timestamp,
        dependencies,
        payload: [payload; PAYLOAD_BYTES],
    })
}

fn staged_event(index: u64, inner_bytes: Vec<u8>) -> Fact {
    Fact::new(
        FactScope::Local,
        0,
        encode_staged(&StagedEventWithDeps { index, inner_bytes }),
    )
}

fn event_context_role() -> Role {
    Role::new("event").expect("valid event context role")
}

fn encode_event(event: &EventWithDeps) -> Vec<u8> {
    assert!(
        event.dependencies.len() <= MAX_DEPS,
        "event_with_deps dependencies exceed fixed field count"
    );
    let mut out = vec![0; ENCODED_BYTES];
    out[0] = TYPE_EVENT_WITH_DEPS;
    out[1..9].copy_from_slice(&event.timestamp.to_be_bytes());
    out[9] = event.dependencies.len() as u8;
    let mut offset = 10;
    for idx in 0..MAX_DEPS {
        let dep = event.dependencies.get(idx).copied().unwrap_or([0; 32]);
        out[offset..offset + 32].copy_from_slice(&dep);
        offset += 32;
    }
    out[offset..offset + PAYLOAD_BYTES].copy_from_slice(&event.payload);
    out
}

fn decode_event(bytes: &[u8]) -> Result<EventWithDeps, String> {
    if bytes.len() != ENCODED_BYTES {
        return Err("event_with_deps length mismatch".to_string());
    }
    if bytes[0] != TYPE_EVENT_WITH_DEPS {
        return Err("unknown event type".to_string());
    }
    let timestamp = u64::from_be_bytes(bytes[1..9].try_into().unwrap());
    let dep_count = bytes[9] as usize;
    if dep_count > MAX_DEPS {
        return Err("event_with_deps dependency count exceeds fixed fields".to_string());
    }

    let mut dependencies = Vec::with_capacity(dep_count);
    let mut offset = 10;
    for idx in 0..MAX_DEPS {
        let dep: FactId = bytes[offset..offset + 32].try_into().unwrap();
        if idx < dep_count {
            dependencies.push(dep);
        } else if dep != [0; 32] {
            return Err("event_with_deps unused dependency field is nonzero".to_string());
        }
        offset += 32;
    }
    let payload = bytes[offset..offset + PAYLOAD_BYTES].try_into().unwrap();
    Ok(EventWithDeps {
        timestamp,
        dependencies,
        payload,
    })
}

fn encode_staged(event: &StagedEventWithDeps) -> Vec<u8> {
    assert_eq!(
        event.inner_bytes.len(),
        ENCODED_BYTES,
        "staged event_with_deps bytes must be fixed width"
    );
    let mut out = vec![0; STAGED_ENCODED_BYTES];
    out[0] = TYPE_STAGED_EVENT_WITH_DEPS;
    out[1..9].copy_from_slice(&event.index.to_be_bytes());
    out[9..].copy_from_slice(&event.inner_bytes);
    out
}

fn decode_staged(bytes: &[u8]) -> Result<StagedEventWithDeps, String> {
    if bytes.len() != STAGED_ENCODED_BYTES {
        return Err("staged event_with_deps length mismatch".to_string());
    }
    if bytes[0] != TYPE_STAGED_EVENT_WITH_DEPS {
        return Err("unknown staged event_with_deps type".to_string());
    }
    let index = u64::from_be_bytes(bytes[1..9].try_into().unwrap());
    let inner_bytes = bytes[9..].to_vec();
    decode_event(&inner_bytes)?;
    Ok(StagedEventWithDeps { index, inner_bytes })
}

#[derive(Debug, Clone, Default)]
struct EventWithDepsProjector;

impl EventWithDepsProjector {
    fn new() -> Self {
        Self
    }
}

impl Projector for EventWithDepsProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        match fact.bytes.first().copied() {
            Some(TYPE_EVENT_WITH_DEPS) => project_event_with_deps(fact, context),
            Some(TYPE_STAGED_EVENT_WITH_DEPS) => project_staged_event(fact),
            _ => Err("unknown event_with_deps fact type".to_string()),
        }
    }
}

fn project_event_with_deps(
    fact: &Fact,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let event = decode_event(&fact.bytes)?;
    let role = event_context_role();
    let mut output = ProjectionOutput::new();

    for dependency in event.dependencies {
        let selector = Selector::from_bytes(dependency);
        let has_dependency = context.offers().iter().any(|offer| {
            offer.role == role && offer.selector == selector && offer.payload_ref == dependency
        });
        if !has_dependency {
            output = output.need(ContextNeed {
                owner: fact.id,
                role: role.clone(),
                scope: fact.scope.clone(),
                selector,
            });
        }
    }

    if output.needs.is_empty() {
        output = output.offer(ContextOffer {
            owner: fact.id,
            role,
            scope: fact.scope.clone(),
            selector: Selector::from_bytes(fact.id),
            payload_ref: fact.id,
        });
    }
    Ok(output)
}

fn project_staged_event(fact: &Fact) -> Result<ProjectionOutput, String> {
    let staged = decode_staged(&fact.bytes)?;
    Ok(ProjectionOutput::new().intent(
        AtomicIntent::PutRow(TableRow {
            table: STAGED_EVENTS_WITH_DEPS,
            key: staged.index.to_be_bytes().to_vec(),
            value: staged.inner_bytes,
        })
        .into_intent(),
    ))
}

#[test]
fn event_with_deps_bridge_resolves_out_of_order_dependencies_by_context() {
    let projector = EventWithDepsProjector::new();
    let matcher = ExactSelectorMatcher::new(event_context_role());
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
    let matcher = ExactSelectorMatcher::new(event_context_role());
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
    let store = Store::open_memory_with_schemas(SCHEMAS).expect("open staged event schema");
    let inner = event_with_deps(42, vec![[1; 32], [2; 32]], 7);
    let staged = staged_event(17, inner.bytes.clone());
    let mut bus = WakeLoop::new();

    bus.submit_fact(staged);
    let projected = bus
        .drain_applying_atomic_rows(
            &EventWithDepsProjector::new(),
            &[],
            &store,
            &[STAGED_EVENTS_WITH_DEPS],
            10,
        )
        .expect("project staged event");
    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 1);
    assert!(bus.intents().is_empty());
    assert_eq!(
        store
            .table_rows(STAGED_EVENTS_WITH_DEPS)
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

        let output = EventWithDepsProjector::new().project(fact, context)?;
        if output.needs.is_empty() && !output.offers.is_empty() {
            self.materialized.set(self.materialized.get() + 1);
        }
        Ok(output)
    }
}
