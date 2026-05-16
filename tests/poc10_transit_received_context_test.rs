use topo::core::context::Selector;
use topo::core::facts::{Fact, FactScope};
use topo::core::matchers::ContextMatcher;
use topo::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use topo::core::wake_loop::WakeLoop;
use topo::protocol::fact_modules::transit_received::fact::{
    TransitReceivedFact, TRANSIT_KIND_CONNECTION_HANDSHAKE,
};
use topo::protocol::fact_modules::transit_received::{layout, project};
use topo::protocol::matchers as context;
use topo::protocol::matchers::ExactSelectorMatcher;

fn received_fact() -> TransitReceivedFact {
    TransitReceivedFact {
        received_fact_id: [11; 32],
        origin_addr: b"127.0.0.1:41001".to_vec(),
        local_endpoint_id: [12; 32],
        sender_endpoint_id: [13; 32],
        transit_kind: TRANSIT_KIND_CONNECTION_HANDSHAKE,
        connection_id: Some([14; 32]),
        request_id: Some([16; 32]),
        frame_hash: [15; 32],
        received_at_local_ms: 1_700_000_123,
    }
}

#[test]
fn transit_received_projector_offers_receive_context_by_received_fact_id() {
    let provenance = received_fact();
    let fact = Fact::new(
        FactScope::Local,
        1,
        layout::encode_fact(&provenance).expect("encode"),
    );
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(fact.clone()));
    let projected = bus
        .drain(&project::TransitReceivedProjector::new(), &[], 10)
        .expect("project receive provenance");

    assert_eq!(projected.projections, 1);
    assert_eq!(projected.intents, 0);
    let standing = bus.context(&fact.id).expect("standing context");
    assert!(standing.needs.is_empty());
    assert_eq!(standing.offers.len(), 1);
    assert_eq!(standing.offers[0].owner, fact.id);
    assert_eq!(standing.offers[0].role, context::transit_received_role());
    assert_eq!(standing.offers[0].scope, FactScope::Local);
    assert_eq!(
        standing.offers[0].selector,
        Selector::from_bytes(provenance.received_fact_id)
    );
    assert_eq!(standing.offers[0].payload_ref, fact.id);
}

#[test]
fn transit_received_offer_wakes_matching_local_need() {
    let provenance = received_fact();
    let received_fact_id = provenance.received_fact_id;
    let waiter = Fact::new(FactScope::Local, 1, b"waiter".to_vec());
    let receive = Fact::new(
        FactScope::Local,
        2,
        layout::encode_fact(&provenance).expect("encode"),
    );
    let matcher = ExactSelectorMatcher::new(context::transit_received_role());
    let matchers = [&matcher as &dyn ContextMatcher];
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(waiter.clone()));
    bus.drain(&WaitingProjector { received_fact_id }, &matchers, 10)
        .expect("waiter projects need");
    assert_eq!(
        bus.context(&waiter.id).expect("waiter context").needs.len(),
        1
    );

    assert!(bus.submit_fact(receive));
    let projected = bus
        .drain(&project::TransitReceivedProjector::new(), &matchers, 1)
        .expect("receive offer wakes need");
    assert_eq!(projected.wakes, 1);
}

#[test]
fn transit_received_projector_rejects_non_local_scope() {
    let fact = Fact::new(
        FactScope::Global,
        1,
        layout::encode_fact(&received_fact()).expect("encode"),
    );
    let mut bus = WakeLoop::new();

    assert!(bus.submit_fact(fact));
    let err = bus
        .drain(&project::TransitReceivedProjector::new(), &[], 10)
        .expect_err("non-local receive provenance must fail");
    assert!(err.contains("Local"), "{err}");
}

struct WaitingProjector {
    received_fact_id: [u8; 32],
}

impl Projector for WaitingProjector {
    fn project(
        &self,
        fact: &Fact,
        _context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        Ok(ProjectionOutput::new().need(context::transit_received_need(
            fact.id,
            self.received_fact_id,
        )))
    }
}
