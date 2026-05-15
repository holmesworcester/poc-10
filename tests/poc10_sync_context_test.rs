use topo::core::event_bus::EventBus;
use topo::core::facts::Fact;
use topo::core::matchers::{ContextMatcher, ExactSelectorMatcher};
use topo::event_modules::sync::context::{self, RangeEventMatcher};
use topo::event_modules::sync::fact::{
    EncryptedRootFact, KeyWrapAvailableFact, SharedEventFact, SyncRangeRequestFact,
};
use topo::event_modules::sync::{layout, project};
use topo::handlers::transit;

#[test]
fn sync_request_sends_encrypted_message_when_out_of_range_dep_and_key_arrive() {
    let workspace = [7; 32];
    let connection = [8; 32];
    let message_event_id = id(9);
    let dep_id = id(10);
    let key_wrap_id = id(11);
    let request = sync_range_request_fact(workspace, connection, 100, 110);
    let message = encrypted_root_fact(workspace, 105, message_event_id, dep_id, key_wrap_id);
    let dep = shared_event_fact(workspace, 12, dep_id);
    let key = key_wrap_available_fact(workspace, 200, key_wrap_id);
    let range_matcher = RangeEventMatcher::new();
    let event_matcher = ExactSelectorMatcher::new(context::exact_event_role());
    let key_matcher = ExactSelectorMatcher::new(context::key_wrap_role());
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
    assert_eq!(
        bus.intents()[0].kind.as_str(),
        transit::TRANSIT_SEND_ON_CONNECTION
    );
    assert_eq!(
        decode_send_fact_ids(&bus.intents()[0]),
        vec![message_event_id, dep_id, key_wrap_id]
    );
    assert!(
        bus.context(&request.id)
            .map(|context| context.needs.is_empty())
            .unwrap_or(true),
        "request should not retain range/dependency/key needs once send is ready"
    );
}

#[test]
fn sync_request_does_not_send_message_before_out_of_range_key_wrap() {
    let workspace = [17; 32];
    let connection = [18; 32];
    let message_event_id = id(19);
    let dep_id = id(20);
    let key_wrap_id = id(21);
    let request = sync_range_request_fact(workspace, connection, 100, 110);
    let message = encrypted_root_fact(workspace, 105, message_event_id, dep_id, key_wrap_id);
    let dep = shared_event_fact(workspace, 1, dep_id);
    let range_matcher = RangeEventMatcher::new();
    let event_matcher = ExactSelectorMatcher::new(context::exact_event_role());
    let key_matcher = ExactSelectorMatcher::new(context::key_wrap_role());
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
        standing
            .needs
            .iter()
            .any(|need| need.role == context::key_wrap_role()
                && need.selector.as_bytes() == key_wrap_id),
        "sync must keep an out-of-range key need until the matching key offer arrives"
    );
}

#[test]
fn sync_request_sends_ready_root_when_an_earlier_root_is_missing_a_key() {
    let workspace = [27; 32];
    let connection = [28; 32];
    let blocked_event_id = id(29);
    let blocked_dep_id = id(30);
    let blocked_key_wrap_id = id(31);
    let ready_event_id = id(32);
    let ready_dep_id = id(33);
    let ready_key_wrap_id = id(34);
    let request = sync_range_request_fact(workspace, connection, 100, 110);
    let blocked = encrypted_root_fact(
        workspace,
        101,
        blocked_event_id,
        blocked_dep_id,
        blocked_key_wrap_id,
    );
    let ready = encrypted_root_fact(
        workspace,
        102,
        ready_event_id,
        ready_dep_id,
        ready_key_wrap_id,
    );
    let blocked_dep = shared_event_fact(workspace, 1, blocked_dep_id);
    let ready_dep = shared_event_fact(workspace, 2, ready_dep_id);
    let ready_key = key_wrap_available_fact(workspace, 3, ready_key_wrap_id);
    let range_matcher = RangeEventMatcher::new();
    let event_matcher = ExactSelectorMatcher::new(context::exact_event_role());
    let key_matcher = ExactSelectorMatcher::new(context::key_wrap_role());
    let matchers = [
        &range_matcher as &dyn ContextMatcher,
        &event_matcher as &dyn ContextMatcher,
        &key_matcher as &dyn ContextMatcher,
    ];
    let projector = project::SyncContextProjector::new();
    let mut bus = EventBus::new();

    for fact in [request, blocked, ready, blocked_dep, ready_dep, ready_key] {
        bus.submit_fact(fact);
    }
    bus.drain(&projector, &matchers, 100)
        .expect("sync should skip blocked root and send ready root");

    assert_eq!(bus.intents().len(), 1);
    assert_eq!(
        decode_send_fact_ids(&bus.intents()[0]),
        vec![ready_event_id, ready_dep_id, ready_key_wrap_id]
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
    event_id: [u8; 32],
    dependency_id: [u8; 32],
    key_wrap_id: [u8; 32],
) -> Fact {
    Fact::new(
        context::workspace_scope(workspace_id),
        timestamp,
        layout::encode_encrypted_root(&EncryptedRootFact {
            workspace_id,
            event_id,
            dependency_id,
            key_wrap_id,
        })
        .expect("encode encrypted root"),
    )
}

fn shared_event_fact(workspace_id: [u8; 32], timestamp: u64, event_id: [u8; 32]) -> Fact {
    Fact::new(
        context::workspace_scope(workspace_id),
        timestamp,
        layout::encode_shared_event(&SharedEventFact {
            workspace_id,
            event_id,
        })
        .expect("encode shared event"),
    )
}

fn key_wrap_available_fact(workspace_id: [u8; 32], timestamp: u64, key_wrap_id: [u8; 32]) -> Fact {
    Fact::new(
        context::workspace_scope(workspace_id),
        timestamp,
        layout::encode_key_wrap_available(&KeyWrapAvailableFact {
            workspace_id,
            key_wrap_id,
        })
        .expect("encode key wrap availability"),
    )
}

fn decode_send_fact_ids(intent: &topo::core::intents::Intent) -> Vec<[u8; 32]> {
    transit::decode_send_on_connection(intent)
        .expect("decode send_on_connection")
        .fact_ids
}

fn id(value: u8) -> [u8; 32] {
    [value; 32]
}
