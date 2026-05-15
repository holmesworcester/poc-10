use topo::core::event_bus::EventBus;
use topo::core::facts::Fact;
use topo::core::matchers::{ContextMatcher, ExactSelectorMatcher};
use topo::event_modules::sync::context::{self, RangeEventMatcher};
use topo::event_modules::sync::fact::{
    DependencyFact, EncryptedRootFact, KeyOfferFact, SyncRangeRequestFact,
};
use topo::event_modules::sync::{layout, project};

#[test]
fn sync_request_sends_encrypted_message_when_out_of_range_dep_and_key_arrive() {
    let workspace = [7; 32];
    let connection = [8; 32];
    let dep_id = id(10);
    let key_id = id(11);
    let request = sync_range_request_fact(workspace, connection, 100, 110);
    let message = encrypted_root_fact(workspace, 105, dep_id, key_id);
    let message_id = message.id;
    let dep = dependency_fact(workspace, 12, dep_id);
    let key = key_offer_fact(workspace, 200, key_id);
    let range_matcher = RangeEventMatcher::new();
    let event_matcher = ExactSelectorMatcher::new(context::exact_event_role());
    let key_matcher = ExactSelectorMatcher::new(context::key_offer_role());
    let matchers = [
        &range_matcher as &dyn ContextMatcher,
        &event_matcher as &dyn ContextMatcher,
        &key_matcher as &dyn ContextMatcher,
    ];
    let projector = project::SyncContextProjector::new();
    let mut bus = EventBus::new();

    bus.submit_fact(request.clone());
    bus.drain(&projector, &matchers, 10)
        .expect("range request waits");
    assert_eq!(bus.context(&request.id).unwrap().needs.len(), 1);

    bus.submit_fact(message.clone());
    let root_seen = bus
        .drain(&projector, &matchers, 10)
        .expect("range root wakes request");
    assert_eq!(root_seen.wakes, 1);
    assert_eq!(bus.context(&request.id).unwrap().needs.len(), 3);
    assert!(bus.intents().is_empty());

    bus.submit_fact(dep);
    bus.submit_fact(key);
    let ready = bus
        .drain(&projector, &matchers, 20)
        .expect("out-of-range dep and key satisfy sync request");

    assert!(ready.wakes >= 1);
    assert_eq!(bus.intents().len(), 1);
    assert_eq!(bus.intents()[0].kind.as_str(), "send_on_connection");
    assert_eq!(
        decode_send_payload(&bus.intents()[0].payload),
        (message_id, dep_id, key_id)
    );
    assert!(
        bus.context(&request.id)
            .map(|context| context.needs.is_empty())
            .unwrap_or(true),
        "request should not retain range/dependency/key needs once send is ready"
    );
}

#[test]
fn sync_request_does_not_send_message_before_out_of_range_key_offer() {
    let workspace = [17; 32];
    let connection = [18; 32];
    let dep_id = id(20);
    let key_id = id(21);
    let request = sync_range_request_fact(workspace, connection, 100, 110);
    let message = encrypted_root_fact(workspace, 105, dep_id, key_id);
    let dep = dependency_fact(workspace, 1, dep_id);
    let range_matcher = RangeEventMatcher::new();
    let event_matcher = ExactSelectorMatcher::new(context::exact_event_role());
    let key_matcher = ExactSelectorMatcher::new(context::key_offer_role());
    let matchers = [
        &range_matcher as &dyn ContextMatcher,
        &event_matcher as &dyn ContextMatcher,
        &key_matcher as &dyn ContextMatcher,
    ];
    let projector = project::SyncContextProjector::new();
    let mut bus = EventBus::new();

    for fact in [request.clone(), message, dep] {
        bus.submit_fact(fact);
    }
    bus.drain(&projector, &matchers, 20)
        .expect("request sees message and dep");

    assert!(bus.intents().is_empty());
    let standing = bus.context(&request.id).expect("request still pending");
    assert!(
        standing.needs.iter().any(
            |need| need.role == context::key_offer_role() && need.selector.as_bytes() == key_id
        ),
        "sync must keep an out-of-range key need until the matching key offer arrives"
    );
}

fn sync_range_request_fact(
    workspace_id: [u8; 32],
    connection_id: [u8; 32],
    start: u64,
    end: u64,
) -> Fact {
    Fact::new(
        context::workspace_scope(workspace_id),
        start,
        layout::encode_sync_range_request(&SyncRangeRequestFact {
            workspace_id,
            connection_id,
            start,
            end,
        })
        .expect("encode sync range request"),
    )
}

fn encrypted_root_fact(
    workspace_id: [u8; 32],
    timestamp: u64,
    dependency_id: [u8; 32],
    key_id: [u8; 32],
) -> Fact {
    Fact::new(
        context::workspace_scope(workspace_id),
        timestamp,
        layout::encode_encrypted_root(&EncryptedRootFact {
            workspace_id,
            dependency_id,
            key_id,
        })
        .expect("encode encrypted root"),
    )
}

fn dependency_fact(workspace_id: [u8; 32], timestamp: u64, event_id: [u8; 32]) -> Fact {
    Fact::new(
        context::workspace_scope(workspace_id),
        timestamp,
        layout::encode_dependency(&DependencyFact {
            workspace_id,
            event_id,
        })
        .expect("encode dependency"),
    )
}

fn key_offer_fact(workspace_id: [u8; 32], timestamp: u64, key_id: [u8; 32]) -> Fact {
    Fact::new(
        context::workspace_scope(workspace_id),
        timestamp,
        layout::encode_key_offer(&KeyOfferFact {
            workspace_id,
            key_id,
        })
        .expect("encode key offer"),
    )
}

fn decode_send_payload(payload: &[u8]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    assert_eq!(payload.len(), 96);
    (
        payload[0..32].try_into().unwrap(),
        payload[32..64].try_into().unwrap(),
        payload[64..96].try_into().unwrap(),
    )
}

fn id(value: u8) -> [u8; 32] {
    [value; 32]
}
