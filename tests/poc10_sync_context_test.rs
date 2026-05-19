use topo::core::crypto;
use topo::core::facts::{Fact, FactScope};
use topo::core::intents::AtomicIntent;
use topo::core::matchers::ContextMatcher;
use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
use topo::core::wake_loop::WakeLoop;
use topo::protocol::facts::content::message::{
    create as message_create,
    fact::{ContentMessageFact, NONCE_BYTES},
    layout as message_layout,
    rows::{decode_opened_message_row, CONTENT_MESSAGE_ROWS, OPENED_MESSAGE_ROWS},
};
use topo::protocol::facts::encryption::fact::LocalKeySecretFact;
use topo::protocol::facts::encryption::layout as encryption_layout;
use topo::protocol::facts::identity::endpoint_shared::{
    fact::{EndpointRole, EndpointSharedFact},
    layout as endpoint_shared_layout,
};
use topo::protocol::facts::identity::user::{fact::UserFact, layout as user_layout};
use topo::protocol::facts::sync::encrypted_root::fact::EncryptedRootFact;
use topo::protocol::facts::sync::encrypted_root::layout as encrypted_root_layout;
use topo::protocol::facts::sync::key_wrap_available::fact::KeyWrapAvailableFact;
use topo::protocol::facts::sync::key_wrap_available::layout as key_wrap_available_layout;
use topo::protocol::facts::sync::range_request::fact::SyncRangeRequestFact;
use topo::protocol::facts::sync::range_request::{
    layout as sync_range_request_layout, project as sync_range_request_project,
};
use topo::protocol::facts::sync::shared_fact::fact::SharedFact;
use topo::protocol::facts::sync::shared_fact::layout as shared_fact_layout;
use topo::protocol::intents::transport::send_facts_on_connection;
use topo::protocol::matchers::ExactSelectorMatcher;
use topo::protocol::matchers::{self as context, RangeFactMatcher};
use topo::protocol::runtime::ProtocolProjector;

const DISPLAY_SECRET: [u8; 32] = [0x66; 32];

#[test]
fn sync_request_sends_encrypted_message_when_out_of_range_dep_and_key_arrive() {
    let workspace = [7; 32];
    let connection = [8; 32];
    let message_fact_id = id(9);
    let dep_id = id(10);
    let key_wrap_id = id(11);
    let request = sync_range_request_fact(workspace, connection, 100, 110);
    let message = encrypted_root_fact(workspace, 105, message_fact_id, dep_id, key_wrap_id);
    let dep = shared_fact_fact(workspace, 12, dep_id);
    let key = key_wrap_available_fact(workspace, 200, key_wrap_id);
    let range_matcher = RangeFactMatcher::new();
    let fact_matcher = ExactSelectorMatcher::new(context::exact_fact_role());
    let key_matcher = ExactSelectorMatcher::new(context::key_wrap_role());
    let matchers = [
        &range_matcher as &dyn ContextMatcher,
        &fact_matcher as &dyn ContextMatcher,
        &key_matcher as &dyn ContextMatcher,
    ];
    let projector = ProtocolProjector;
    let mut bus = WakeLoop::new();

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
        send_facts_on_connection::SEND_FACTS_ON_CONNECTION
    );
    assert_eq!(
        decode_send_fact_ids(&bus.intents()[0]),
        vec![message_fact_id, dep_id, key_wrap_id]
    );
    assert!(
        bus.context(&request.id)
            .map(|context| context.needs.is_empty())
            .unwrap_or(true),
        "request should not retain range/dependency/key needs once send is ready"
    );
}

#[test]
fn dep_aware_sync_displays_encrypted_out_of_range_message_fast() {
    let workspace = [67; 32];
    let connection = [68; 32];
    let message_fact_id = id(69);
    let dep_id = id(70);
    let key_wrap_id = id(71);
    let day_ms = 86_400_000;
    let request = sync_range_request_fact(workspace, connection, day_ms, day_ms + 10);
    let message = encrypted_root_fact(workspace, day_ms + 5, message_fact_id, dep_id, key_wrap_id);
    let dep = shared_fact_fact(workspace, 0, dep_id);
    let key = key_wrap_available_fact(workspace, day_ms * 2, key_wrap_id);
    let range_matcher = RangeFactMatcher::new();
    let fact_matcher = ExactSelectorMatcher::new(context::exact_fact_role());
    let key_matcher = ExactSelectorMatcher::new(context::key_wrap_role());
    let matchers = [
        &range_matcher as &dyn ContextMatcher,
        &fact_matcher as &dyn ContextMatcher,
        &key_matcher as &dyn ContextMatcher,
    ];
    let projector = ProtocolProjector;
    let mut bus = WakeLoop::new();

    bus.submit_fact(message);
    bus.submit_fact(dep);
    bus.submit_fact(key);
    for value in 100..164 {
        bus.submit_fact(shared_fact_fact(workspace, value, id(value as u8)));
        bus.submit_fact(key_wrap_available_fact(
            workspace,
            day_ms * 3 + value,
            id((value + 64) as u8),
        ));
    }
    bus.drain(&projector, &matchers, 300)
        .expect("pre-existing sync context offers should project");
    assert!(bus.intents().is_empty());

    bus.submit_fact(request.clone());
    let ready = bus
        .drain(&projector, &matchers, 4)
        .expect("range request should resolve from matched context");

    assert!(
        ready.projections <= 4,
        "sync should use range/exact context matches instead of scanning unrelated history: {ready:?}"
    );
    assert_eq!(bus.intents().len(), 1);
    assert_eq!(
        decode_send_fact_ids(&bus.intents()[0]),
        vec![message_fact_id, dep_id, key_wrap_id]
    );
    assert!(
        bus.context(&request.id)
            .map(|context| context.needs.is_empty())
            .unwrap_or(true),
        "request should not keep key needs once out-of-range key context is matched"
    );

    let signer_id = id(72);
    let author_id = id(75);
    let frontier = id(73);
    let leaf = id(74);
    let content_message = content_message_fact(
        workspace,
        author_id,
        signer_id,
        frontier,
        day_ms / 60_000,
        leaf,
    );
    let signer_fact = endpoint_signer_fact(workspace, author_id, signer_id);
    let author_fact = author_user_fact(workspace, author_id);
    let secret_fact = local_key_secret_fact(workspace, frontier, id(73));
    let projector = ProtocolProjector;
    let output = projector
        .project(
            &content_message,
            &ProjectionContext::from_matches(vec![
                signer_match(&content_message, &signer_fact, workspace, signer_id),
                author_match(&content_message, &author_fact, author_id),
                secret_match(&content_message, &secret_fact, workspace, frontier, leaf),
            ]),
        )
        .expect("content message should resolve from matched key context");

    assert!(
        output
            .needs
            .iter()
            .any(|need| need.role == context::secret_role()),
        "message should keep its secret need declared even after matched key context"
    );
    let content_rows = output
        .intents
        .iter()
        .filter_map(|intent| AtomicIntent::from_intent(intent, &[CONTENT_MESSAGE_ROWS]).ok())
        .map(|intent| match intent {
            AtomicIntent::PutRow(row) => row,
            AtomicIntent::DeleteRow(_) => panic!("content projection should put a row"),
        })
        .collect::<Vec<_>>();
    assert_eq!(content_rows.len(), 1);
    let opened_rows = output
        .intents
        .iter()
        .filter_map(|intent| AtomicIntent::from_intent(intent, &[OPENED_MESSAGE_ROWS]).ok())
        .map(|intent| match intent {
            AtomicIntent::PutRow(row) => row,
            AtomicIntent::DeleteRow(_) => panic!("opened projection should put a row"),
        })
        .collect::<Vec<_>>();
    assert_eq!(opened_rows.len(), 1);
    let opened_row = &opened_rows[0];
    assert_eq!(
        decode_opened_message_row(&opened_row.key, &opened_row.value)
            .expect("decode opened row")
            .message_id,
        content_message.id
    );
}

#[test]
fn sync_request_does_not_send_message_before_out_of_range_key_wrap() {
    let workspace = [17; 32];
    let connection = [18; 32];
    let message_fact_id = id(19);
    let dep_id = id(20);
    let key_wrap_id = id(21);
    let request = sync_range_request_fact(workspace, connection, 100, 110);
    let message = encrypted_root_fact(workspace, 105, message_fact_id, dep_id, key_wrap_id);
    let dep = shared_fact_fact(workspace, 1, dep_id);
    let range_matcher = RangeFactMatcher::new();
    let fact_matcher = ExactSelectorMatcher::new(context::exact_fact_role());
    let key_matcher = ExactSelectorMatcher::new(context::key_wrap_role());
    let matchers = [
        &range_matcher as &dyn ContextMatcher,
        &fact_matcher as &dyn ContextMatcher,
        &key_matcher as &dyn ContextMatcher,
    ];
    let projector = ProtocolProjector;
    let mut bus = WakeLoop::new();

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
    let blocked_fact_id = id(29);
    let blocked_dep_id = id(30);
    let blocked_key_wrap_id = id(31);
    let ready_fact_id = id(32);
    let ready_dep_id = id(33);
    let ready_key_wrap_id = id(34);
    let request = sync_range_request_fact(workspace, connection, 100, 110);
    let blocked = encrypted_root_fact(
        workspace,
        101,
        blocked_fact_id,
        blocked_dep_id,
        blocked_key_wrap_id,
    );
    let ready = encrypted_root_fact(
        workspace,
        102,
        ready_fact_id,
        ready_dep_id,
        ready_key_wrap_id,
    );
    let blocked_dep = shared_fact_fact(workspace, 1, blocked_dep_id);
    let ready_dep = shared_fact_fact(workspace, 2, ready_dep_id);
    let ready_key = key_wrap_available_fact(workspace, 3, ready_key_wrap_id);
    let range_matcher = RangeFactMatcher::new();
    let fact_matcher = ExactSelectorMatcher::new(context::exact_fact_role());
    let key_matcher = ExactSelectorMatcher::new(context::key_wrap_role());
    let matchers = [
        &range_matcher as &dyn ContextMatcher,
        &fact_matcher as &dyn ContextMatcher,
        &key_matcher as &dyn ContextMatcher,
    ];
    let projector = ProtocolProjector;
    let mut bus = WakeLoop::new();

    for fact in [
        request.clone(),
        blocked,
        ready,
        blocked_dep,
        ready_dep,
        ready_key,
    ] {
        bus.submit_fact(fact);
    }
    bus.drain(&projector, &matchers, 100)
        .expect("sync should skip blocked root and send ready root");

    assert_eq!(bus.intents().len(), 1);
    assert_eq!(
        decode_send_fact_ids(&bus.intents()[0]),
        vec![ready_fact_id, ready_dep_id, ready_key_wrap_id]
    );
    let standing = bus
        .context(&request.id)
        .expect("incomplete root should keep request context");
    assert!(
        standing.needs.iter().any(|need| {
            need.role == context::key_wrap_role() && need.selector.as_bytes() == blocked_key_wrap_id
        }),
        "sending a complete root must not drop the missing key need for another in-range root"
    );
}

#[test]
fn sync_request_emits_all_complete_roots_in_deterministic_order() {
    let workspace = [37; 32];
    let connection = [38; 32];
    let early_fact_id = id(39);
    let early_dep_id = id(40);
    let early_key_wrap_id = id(41);
    let late_fact_id = id(42);
    let late_dep_id = id(43);
    let late_key_wrap_id = id(44);
    let request = sync_range_request_fact(workspace, connection, 100, 110);
    let late = encrypted_root_fact(workspace, 109, late_fact_id, late_dep_id, late_key_wrap_id);
    let early = encrypted_root_fact(
        workspace,
        101,
        early_fact_id,
        early_dep_id,
        early_key_wrap_id,
    );
    let range_matcher = RangeFactMatcher::new();
    let fact_matcher = ExactSelectorMatcher::new(context::exact_fact_role());
    let key_matcher = ExactSelectorMatcher::new(context::key_wrap_role());
    let matchers = [
        &range_matcher as &dyn ContextMatcher,
        &fact_matcher as &dyn ContextMatcher,
        &key_matcher as &dyn ContextMatcher,
    ];
    let projector = ProtocolProjector;
    let mut bus = WakeLoop::new();

    for fact in [
        request.clone(),
        late,
        early,
        shared_fact_fact(workspace, 1, late_dep_id),
        key_wrap_available_fact(workspace, 1, late_key_wrap_id),
        shared_fact_fact(workspace, 1, early_dep_id),
        key_wrap_available_fact(workspace, 1, early_key_wrap_id),
    ] {
        bus.submit_fact(fact);
    }
    bus.drain(&projector, &matchers, 100)
        .expect("sync should send every complete root");

    let sent = bus
        .intents()
        .iter()
        .map(decode_send_fact_ids)
        .collect::<Vec<_>>();
    assert_eq!(
        sent,
        vec![
            vec![early_fact_id, early_dep_id, early_key_wrap_id],
            vec![late_fact_id, late_dep_id, late_key_wrap_id],
        ],
        "complete roots should be sent in timestamp/fact-id order, independent of submission order"
    );
    assert!(
        bus.context(&request.id)
            .map(|context| context.needs.is_empty())
            .unwrap_or(true),
        "a fully complete range request should not retain broad range context"
    );
}

#[test]
fn sync_range_matching_ignores_out_of_range_roots_and_their_context() {
    let workspace = [47; 32];
    let connection = [48; 32];
    let in_range_fact_id = id(49);
    let in_range_dep_id = id(50);
    let in_range_key_wrap_id = id(51);
    let out_of_range_fact_id = id(52);
    let out_of_range_dep_id = id(53);
    let out_of_range_key_wrap_id = id(54);
    let request = sync_range_request_fact(workspace, connection, 100, 110);
    let in_range = encrypted_root_fact(
        workspace,
        105,
        in_range_fact_id,
        in_range_dep_id,
        in_range_key_wrap_id,
    );
    let out_of_range = encrypted_root_fact(
        workspace,
        111,
        out_of_range_fact_id,
        out_of_range_dep_id,
        out_of_range_key_wrap_id,
    );
    let range_matcher = RangeFactMatcher::new();
    let fact_matcher = ExactSelectorMatcher::new(context::exact_fact_role());
    let key_matcher = ExactSelectorMatcher::new(context::key_wrap_role());
    let matchers = [
        &range_matcher as &dyn ContextMatcher,
        &fact_matcher as &dyn ContextMatcher,
        &key_matcher as &dyn ContextMatcher,
    ];
    let projector = ProtocolProjector;
    let mut bus = WakeLoop::new();

    for fact in [
        request.clone(),
        out_of_range,
        in_range,
        shared_fact_fact(workspace, 1, out_of_range_dep_id),
        key_wrap_available_fact(workspace, 1, out_of_range_key_wrap_id),
    ] {
        bus.submit_fact(fact);
    }
    bus.drain(&projector, &matchers, 100)
        .expect("sync should inspect only matching range roots");

    assert!(bus.intents().is_empty());
    let standing = bus.context(&request.id).expect("request still waiting");
    assert!(
        standing.needs.iter().any(|need| {
            need.role == context::key_wrap_role()
                && need.selector.as_bytes() == in_range_key_wrap_id
        }),
        "in-range root should produce an exact key-wrap need"
    );
    assert!(
        standing.needs.iter().all(|need| {
            need.selector.as_bytes() != out_of_range_dep_id
                && need.selector.as_bytes() != out_of_range_key_wrap_id
        }),
        "out-of-range roots must not create exact dependency/key needs"
    );
}

#[test]
fn sync_projector_revalidates_matched_range_payload() {
    let workspace = [57; 32];
    let connection = [58; 32];
    let message_fact_id = id(59);
    let dep_id = id(60);
    let key_wrap_id = id(61);
    let request = sync_range_request_fact(workspace, connection, 100, 110);
    let payload = encrypted_root_fact(workspace, 105, message_fact_id, dep_id, key_wrap_id);
    let range_need =
        context::range_fact_need(request.id, context::workspace_scope(workspace), 100, 110);
    let mismatched_offer = context::range_fact_offer(
        payload.id,
        context::workspace_scope(workspace),
        105,
        id(62),
        dep_id,
        key_wrap_id,
    );
    let projection_context = ProjectionContext::from_matches(vec![MatchedContext {
        need: range_need,
        offer: mismatched_offer,
        payload,
    }]);

    let err = sync_range_request_project::SyncRangeRequestProjector::new()
        .project(&request, &projection_context)
        .expect_err("matched context must be semantically revalidated");
    assert!(
        err.contains("range context offer does not match"),
        "unexpected sync validation error: {err}"
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
        sync_range_request_layout::encode_fact(&SyncRangeRequestFact {
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
    fact_id: [u8; 32],
    dependency_id: [u8; 32],
    key_wrap_id: [u8; 32],
) -> Fact {
    Fact::new(
        context::workspace_scope(workspace_id),
        timestamp,
        encrypted_root_layout::encode_fact(&EncryptedRootFact {
            workspace_id,
            fact_id,
            dependency_id,
            key_wrap_id,
        })
        .expect("encode encrypted root"),
    )
}

fn shared_fact_fact(workspace_id: [u8; 32], timestamp: u64, fact_id: [u8; 32]) -> Fact {
    Fact::new(
        context::workspace_scope(workspace_id),
        timestamp,
        shared_fact_layout::encode_fact(&SharedFact {
            workspace_id,
            fact_id,
        })
        .expect("encode shared fact"),
    )
}

fn key_wrap_available_fact(workspace_id: [u8; 32], timestamp: u64, key_wrap_id: [u8; 32]) -> Fact {
    Fact::new(
        context::workspace_scope(workspace_id),
        timestamp,
        key_wrap_available_layout::encode_fact(&KeyWrapAvailableFact {
            workspace_id,
            key_wrap_id,
        })
        .expect("encode key wrap availability"),
    )
}

fn content_message_fact(
    workspace_id: [u8; 32],
    author_user_id: [u8; 32],
    signer_id: [u8; 32],
    frontier_id: [u8; 32],
    minute: u64,
    leaf_id: [u8; 32],
) -> Fact {
    Fact::new(
        context::workspace_scope(workspace_id),
        minute,
        message_layout::encode_fact(&ContentMessageFact {
            workspace_id,
            created_at_ms: minute * 60_000,
            author_user_id,
            signer_id,
            frontier_id,
            local_history_node_secret_id: [76; 32],
            expires_at_minute: u64::MAX,
            disappearing_setting_id: [77; 32],
            minute,
            leaf_id,
            nonce: [78; NONCE_BYTES],
            ciphertext: encrypted_display_body(workspace_id, frontier_id, minute),
        })
        .expect("encode content message"),
    )
}

fn encrypted_display_body(workspace_id: [u8; 32], frontier_id: [u8; 32], minute: u64) -> Vec<u8> {
    let plaintext = message_create::pad_plaintext(b"display").expect("pad display plaintext");
    crypto::xchacha20poly1305_encrypt(
        &DISPLAY_SECRET,
        &message_create::associated_data(workspace_id, frontier_id, minute),
        &[78; NONCE_BYTES],
        &plaintext,
    )
    .expect("encrypt display message")
}

fn endpoint_signer_fact(
    workspace_id: [u8; 32],
    author_user_id: [u8; 32],
    signer_id: [u8; 32],
) -> Fact {
    Fact::new(
        FactScope::Global,
        1,
        endpoint_shared_layout::encode_fact(&EndpointSharedFact {
            created_at_ms: 1,
            workspace_id,
            user_authority_fact_id: author_user_id,
            endpoint_id: signer_id,
            signing_public_key: [79; 32],
            endpoint_role: EndpointRole::Device,
            device_name: "display".to_string(),
        })
        .expect("encode endpoint shared"),
    )
}

fn author_user_fact(workspace_id: [u8; 32], author_user_id: [u8; 32]) -> Fact {
    Fact {
        id: author_user_id,
        scope: FactScope::Global,
        timestamp: 1,
        bytes: user_layout::encode_fact(&UserFact {
            created_at_ms: 1,
            workspace_id,
            public_key: [80; 32],
            username: "display-author".to_string(),
        })
        .expect("encode user"),
    }
}

fn signer_match(
    message_fact: &Fact,
    signer_fact: &Fact,
    workspace_id: [u8; 32],
    signer_id: [u8; 32],
) -> MatchedContext {
    let scope = context::workspace_scope(workspace_id);
    MatchedContext {
        need: context::signer_need(message_fact.id, scope.clone(), signer_id),
        offer: context::signer_offer(signer_fact.id, scope, signer_id),
        payload: signer_fact.clone(),
    }
}

fn author_match(message_fact: &Fact, author_fact: &Fact, author_id: [u8; 32]) -> MatchedContext {
    MatchedContext {
        need: context::exact_need(message_fact.id, context::user_role(), author_id),
        offer: context::exact_offer(author_fact.id, context::user_role()),
        payload: author_fact.clone(),
    }
}

fn secret_match(
    message_fact: &Fact,
    secret_fact: &Fact,
    workspace_id: [u8; 32],
    frontier_id: [u8; 32],
    leaf_id: [u8; 32],
) -> MatchedContext {
    let scope = context::workspace_scope(workspace_id);
    let minute = message_layout::decode_fact(message_fact.body())
        .expect("decode content message")
        .minute;
    MatchedContext {
        need: context::secret_need(
            message_fact.id,
            scope.clone(),
            workspace_id,
            frontier_id,
            minute,
            leaf_id,
        ),
        offer: context::secret_offer(
            secret_fact.id,
            scope,
            workspace_id,
            frontier_id,
            0,
            u64::MAX,
            0,
            [0; 32],
        ),
        payload: secret_fact.clone(),
    }
}

fn local_key_secret_fact(
    workspace_id: [u8; 32],
    frontier_id: [u8; 32],
    owner_endpoint_id: [u8; 32],
) -> Fact {
    Fact::new(
        topo::core::facts::FactScope::Local,
        1,
        encryption_layout::encode_local_key_secret(&LocalKeySecretFact {
            workspace_id,
            frontier_id,
            owner_endpoint_id,
            created_at_ms: 1,
            key_secret: DISPLAY_SECRET,
        })
        .expect("encode local key secret"),
    )
}

fn decode_send_fact_ids(intent: &topo::core::intents::Intent) -> Vec<[u8; 32]> {
    send_facts_on_connection::decode_send_facts_on_connection(intent)
        .expect("decode send_facts_on_connection")
        .fact_ids
}

fn id(value: u8) -> [u8; 32] {
    [value; 32]
}
