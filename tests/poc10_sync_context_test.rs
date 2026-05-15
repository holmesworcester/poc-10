use topo::core::context::{ContextNeed, ContextOffer, Role, Selector};
use topo::core::facts::{Fact, FactId, FactScope, ScopeKind};
use topo::core::intents::{Intent, IntentExecution, IntentKind};
use topo::core::matchers::{ContextMatch, ContextMatcher, ExactSelectorMatcher};
use topo::core::projection::{run_projection, ProjectionContext, ProjectionOutput, Projector};

const TYPE_SYNC_RANGE_REQUEST: u8 = 1;
const TYPE_ENCRYPTED_EVENT: u8 = 2;
const TYPE_DEP_EVENT: u8 = 3;
const TYPE_KEY_OFFER: u8 = 4;

#[test]
fn sync_request_sends_encrypted_message_when_out_of_range_dep_and_key_arrive() {
    let workspace = [7; 32];
    let connection = [8; 32];
    let dep_id = id(10);
    let key_id = id(11);
    let message = encrypted_event_fact(workspace, 105, dep_id, key_id);
    let message_id = message.id;
    let dep = dep_event_fact(workspace, 12, dep_id);
    let key = key_offer_fact(workspace, 200, key_id);
    let request = sync_range_request_fact(workspace, connection, 100, 110);
    let projector = SyncContextProjector;
    let range_matcher = RangeEventMatcher::new();
    let event_matcher = ExactSelectorMatcher::new(exact_event_role());
    let key_matcher = ExactSelectorMatcher::new(key_offer_role());

    let requested = run_projection(&projector, &request, &Default::default(), Vec::new())
        .expect("request posts range need");
    assert_eq!(requested.context.needs.len(), 1);

    let root_offer = project_offers(&projector, &message)[0].clone();
    assert_eq!(
        range_matcher
            .match_new_offer(&root_offer, &requested.context.needs)
            .len(),
        1
    );

    let waiting_for_deps = run_projection(
        &projector,
        &request,
        &requested.context,
        vec![root_offer.clone()],
    )
    .expect("range request sees encrypted root");
    assert!(waiting_for_deps.intents.is_empty());
    assert_eq!(waiting_for_deps.context.needs.len(), 3);

    let dep_offer = project_offers(&projector, &dep)[0].clone();
    assert_eq!(
        event_matcher
            .match_new_offer(&dep_offer, &waiting_for_deps.context.needs)
            .len(),
        1
    );

    let key_offer = project_offers(&projector, &key)[0].clone();
    assert_eq!(
        key_matcher
            .match_new_offer(&key_offer, &waiting_for_deps.context.needs)
            .len(),
        1
    );

    let ready = run_projection(
        &projector,
        &request,
        &waiting_for_deps.context,
        vec![root_offer, dep_offer, key_offer],
    )
    .expect("out-of-range dep and key satisfy sync request");

    assert!(ready.context.needs.is_empty());
    assert_eq!(ready.intents.len(), 1);
    assert_eq!(ready.intents[0].kind.as_str(), "send_on_connection");
    assert_eq!(
        decode_send_payload(&ready.intents[0].payload),
        (message_id, dep_id, key_id)
    );
}

#[test]
fn sync_request_does_not_send_message_before_out_of_range_key_offer() {
    let workspace = [17; 32];
    let connection = [18; 32];
    let dep_id = id(20);
    let key_id = id(21);
    let message = encrypted_event_fact(workspace, 105, dep_id, key_id);
    let dep = dep_event_fact(workspace, 1, dep_id);
    let request = sync_range_request_fact(workspace, connection, 100, 110);
    let projector = SyncContextProjector;
    let range_matcher = RangeEventMatcher::new();
    let event_matcher = ExactSelectorMatcher::new(exact_event_role());

    let requested = run_projection(&projector, &request, &Default::default(), Vec::new())
        .expect("request posts range need");
    let root_offer = project_offers(&projector, &message)[0].clone();
    assert_eq!(
        range_matcher
            .match_new_offer(&root_offer, &requested.context.needs)
            .len(),
        1
    );
    let waiting_for_deps = run_projection(
        &projector,
        &request,
        &requested.context,
        vec![root_offer.clone()],
    )
    .expect("range request sees encrypted root");
    let dep_offer = project_offers(&projector, &dep)[0].clone();
    assert_eq!(
        event_matcher
            .match_new_offer(&dep_offer, &waiting_for_deps.context.needs)
            .len(),
        1
    );

    let waiting = run_projection(
        &projector,
        &request,
        &waiting_for_deps.context,
        vec![root_offer, dep_offer],
    )
    .expect("request waits for out-of-range key");

    assert!(waiting.intents.is_empty());
    let standing = &waiting.context;
    assert!(
        standing
            .needs
            .iter()
            .any(|need| need.role == key_offer_role()
                && need.selector == Selector::from_bytes(key_id))
    );
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SyncRangeRequest {
    workspace: FactId,
    connection: FactId,
    start: u64,
    end: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EncryptedEvent {
    workspace: FactId,
    timestamp: u64,
    dependency_id: FactId,
    key_id: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DepEvent {
    workspace: FactId,
    event_id: FactId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KeyOffer {
    workspace: FactId,
    key_id: FactId,
}

#[derive(Debug, Clone, Default)]
struct SyncContextProjector;

impl Projector for SyncContextProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        match fact.bytes.first().copied() {
            Some(TYPE_SYNC_RANGE_REQUEST) => project_sync_range_request(fact, context),
            Some(TYPE_ENCRYPTED_EVENT) => project_encrypted_event(fact),
            Some(TYPE_DEP_EVENT) => project_dep_event(fact),
            Some(TYPE_KEY_OFFER) => project_key_offer(fact),
            _ => Err("unknown sync context test fact".to_string()),
        }
    }
}

fn project_sync_range_request(
    fact: &Fact,
    context: &ProjectionContext,
) -> Result<ProjectionOutput, String> {
    let request = decode_sync_range_request(&fact.bytes)?;
    let scope = workspace_scope(request.workspace);
    require_scope(fact, &scope)?;
    let range_need = ContextNeed {
        owner: fact.id,
        role: range_event_role(),
        scope: scope.clone(),
        selector: range_need_selector(request.start, request.end),
    };
    let Some(root) = context
        .offers()
        .iter()
        .find(|offer| offer.role == range_event_role())
        .and_then(|offer| decode_range_offer_selector(&offer.selector).map(|root| (offer, root)))
    else {
        return Ok(ProjectionOutput::new().need(range_need));
    };
    let (root_offer, root) = root;
    let dep_need = ContextNeed {
        owner: fact.id,
        role: exact_event_role(),
        scope: scope.clone(),
        selector: Selector::from_bytes(root.dependency_id),
    };
    let key_need = ContextNeed {
        owner: fact.id,
        role: key_offer_role(),
        scope,
        selector: Selector::from_bytes(root.key_id),
    };
    let has_dep = context
        .offers()
        .iter()
        .any(|offer| offer.role == dep_need.role && offer.selector == dep_need.selector);
    let has_key = context
        .offers()
        .iter()
        .any(|offer| offer.role == key_need.role && offer.selector == key_need.selector);

    if has_dep && has_key {
        return Ok(ProjectionOutput::new().intent(send_on_connection_intent(
            request.connection,
            root_offer.payload_ref,
            root.dependency_id,
            root.key_id,
        )));
    }

    Ok(ProjectionOutput::new()
        .need(range_need)
        .need(dep_need)
        .need(key_need))
}

fn project_encrypted_event(fact: &Fact) -> Result<ProjectionOutput, String> {
    let event = decode_encrypted_event(&fact.bytes)?;
    let scope = workspace_scope(event.workspace);
    require_scope(fact, &scope)?;
    Ok(ProjectionOutput::new()
        .offer(ContextOffer {
            owner: fact.id,
            role: range_event_role(),
            scope: scope.clone(),
            selector: range_offer_selector(event.timestamp, event.dependency_id, event.key_id),
            payload_ref: fact.id,
        })
        .offer(ContextOffer {
            owner: fact.id,
            role: exact_event_role(),
            scope,
            selector: Selector::from_bytes(fact.id),
            payload_ref: fact.id,
        }))
}

fn project_dep_event(fact: &Fact) -> Result<ProjectionOutput, String> {
    let event = decode_dep_event(&fact.bytes)?;
    let scope = workspace_scope(event.workspace);
    require_scope(fact, &scope)?;
    Ok(ProjectionOutput::new().offer(ContextOffer {
        owner: fact.id,
        role: exact_event_role(),
        scope,
        selector: Selector::from_bytes(event.event_id),
        payload_ref: event.event_id,
    }))
}

fn project_key_offer(fact: &Fact) -> Result<ProjectionOutput, String> {
    let key = decode_key_offer(&fact.bytes)?;
    let scope = workspace_scope(key.workspace);
    require_scope(fact, &scope)?;
    Ok(ProjectionOutput::new().offer(ContextOffer {
        owner: fact.id,
        role: key_offer_role(),
        scope,
        selector: Selector::from_bytes(key.key_id),
        payload_ref: fact.id,
    }))
}

fn project_offers(projector: &SyncContextProjector, fact: &Fact) -> Vec<ContextOffer> {
    projector
        .project(fact, &ProjectionContext::new(Vec::new()))
        .expect("project test fact")
        .offers
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RangeEventMatcher {
    role: Role,
}

impl RangeEventMatcher {
    fn new() -> Self {
        Self {
            role: range_event_role(),
        }
    }
}

impl ContextMatcher for RangeEventMatcher {
    fn role(&self) -> &Role {
        &self.role
    }

    fn match_new_need(
        &self,
        need: &ContextNeed,
        existing_offers: &[ContextOffer],
    ) -> Vec<ContextMatch> {
        if need.role != self.role {
            return Vec::new();
        }
        existing_offers
            .iter()
            .filter_map(|offer| range_event_match(need, offer))
            .collect()
    }

    fn match_new_offer(
        &self,
        offer: &ContextOffer,
        existing_needs: &[ContextNeed],
    ) -> Vec<ContextMatch> {
        if offer.role != self.role {
            return Vec::new();
        }
        existing_needs
            .iter()
            .filter_map(|need| range_event_match(need, offer))
            .collect()
    }
}

fn range_event_match(need: &ContextNeed, offer: &ContextOffer) -> Option<ContextMatch> {
    if need.role != offer.role || need.scope != offer.scope {
        return None;
    }
    let (start, end) = decode_range_need_selector(&need.selector)?;
    let offer_selector = decode_range_offer_selector(&offer.selector)?;
    if offer_selector.timestamp < start || offer_selector.timestamp > end {
        return None;
    }
    Some(ContextMatch {
        need_owner: need.owner,
        offer_owner: offer.owner,
        payload_ref: offer.payload_ref,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RangeOfferSelector {
    timestamp: u64,
    dependency_id: FactId,
    key_id: FactId,
}

fn sync_range_request_fact(workspace: FactId, connection: FactId, start: u64, end: u64) -> Fact {
    Fact::new(
        workspace_scope(workspace),
        start,
        encode_sync_range_request(SyncRangeRequest {
            workspace,
            connection,
            start,
            end,
        }),
    )
}

fn encrypted_event_fact(
    workspace: FactId,
    timestamp: u64,
    dependency_id: FactId,
    key_id: FactId,
) -> Fact {
    Fact::new(
        workspace_scope(workspace),
        timestamp,
        encode_encrypted_event(EncryptedEvent {
            workspace,
            timestamp,
            dependency_id,
            key_id,
        }),
    )
}

fn dep_event_fact(workspace: FactId, timestamp: u64, event_id: FactId) -> Fact {
    Fact::new(
        workspace_scope(workspace),
        timestamp,
        encode_dep_event(DepEvent {
            workspace,
            event_id,
        }),
    )
}

fn key_offer_fact(workspace: FactId, timestamp: u64, key_id: FactId) -> Fact {
    Fact::new(
        workspace_scope(workspace),
        timestamp,
        encode_key_offer(KeyOffer { workspace, key_id }),
    )
}

fn send_on_connection_intent(
    connection: FactId,
    event_id: FactId,
    dependency_id: FactId,
    key_id: FactId,
) -> Intent {
    let mut key = Vec::with_capacity(64);
    key.extend_from_slice(&connection);
    key.extend_from_slice(&event_id);
    let mut payload = Vec::with_capacity(96);
    payload.extend_from_slice(&event_id);
    payload.extend_from_slice(&dependency_id);
    payload.extend_from_slice(&key_id);
    Intent::new(
        IntentKind::new("send_on_connection").expect("valid intent kind"),
        IntentExecution::Deferred,
        key,
        payload,
    )
}

fn decode_send_payload(payload: &[u8]) -> (FactId, FactId, FactId) {
    assert_eq!(payload.len(), 96);
    (
        payload[0..32].try_into().unwrap(),
        payload[32..64].try_into().unwrap(),
        payload[64..96].try_into().unwrap(),
    )
}

fn workspace_scope(workspace: FactId) -> FactScope {
    FactScope::Scoped {
        kind: ScopeKind::new("workspace").expect("valid workspace scope"),
        id: workspace,
    }
}

fn range_event_role() -> Role {
    Role::new("sync_range_event").expect("valid range role")
}

fn exact_event_role() -> Role {
    Role::new("sync_exact_event").expect("valid exact event role")
}

fn key_offer_role() -> Role {
    Role::new("sync_key_offer").expect("valid key offer role")
}

fn range_need_selector(start: u64, end: u64) -> Selector {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&start.to_be_bytes());
    bytes.extend_from_slice(&end.to_be_bytes());
    Selector::from_bytes(bytes)
}

fn decode_range_need_selector(selector: &Selector) -> Option<(u64, u64)> {
    let bytes = selector.as_bytes();
    if bytes.len() != 16 {
        return None;
    }
    Some((
        u64::from_be_bytes(bytes[0..8].try_into().ok()?),
        u64::from_be_bytes(bytes[8..16].try_into().ok()?),
    ))
}

fn range_offer_selector(timestamp: u64, dependency_id: FactId, key_id: FactId) -> Selector {
    let mut bytes = Vec::with_capacity(72);
    bytes.extend_from_slice(&timestamp.to_be_bytes());
    bytes.extend_from_slice(&dependency_id);
    bytes.extend_from_slice(&key_id);
    Selector::from_bytes(bytes)
}

fn decode_range_offer_selector(selector: &Selector) -> Option<RangeOfferSelector> {
    let bytes = selector.as_bytes();
    if bytes.len() != 72 {
        return None;
    }
    Some(RangeOfferSelector {
        timestamp: u64::from_be_bytes(bytes[0..8].try_into().ok()?),
        dependency_id: bytes[8..40].try_into().ok()?,
        key_id: bytes[40..72].try_into().ok()?,
    })
}

fn encode_sync_range_request(request: SyncRangeRequest) -> Vec<u8> {
    let mut out = Vec::with_capacity(81);
    out.push(TYPE_SYNC_RANGE_REQUEST);
    out.extend_from_slice(&request.workspace);
    out.extend_from_slice(&request.connection);
    out.extend_from_slice(&request.start.to_be_bytes());
    out.extend_from_slice(&request.end.to_be_bytes());
    out
}

fn decode_sync_range_request(bytes: &[u8]) -> Result<SyncRangeRequest, String> {
    if bytes.len() != 81 || bytes[0] != TYPE_SYNC_RANGE_REQUEST {
        return Err("invalid sync range request".to_string());
    }
    Ok(SyncRangeRequest {
        workspace: bytes[1..33].try_into().unwrap(),
        connection: bytes[33..65].try_into().unwrap(),
        start: u64::from_be_bytes(bytes[65..73].try_into().unwrap()),
        end: u64::from_be_bytes(bytes[73..81].try_into().unwrap()),
    })
}

fn encode_encrypted_event(event: EncryptedEvent) -> Vec<u8> {
    let mut out = Vec::with_capacity(105);
    out.push(TYPE_ENCRYPTED_EVENT);
    out.extend_from_slice(&event.workspace);
    out.extend_from_slice(&event.timestamp.to_be_bytes());
    out.extend_from_slice(&event.dependency_id);
    out.extend_from_slice(&event.key_id);
    out
}

fn decode_encrypted_event(bytes: &[u8]) -> Result<EncryptedEvent, String> {
    if bytes.len() != 105 || bytes[0] != TYPE_ENCRYPTED_EVENT {
        return Err("invalid encrypted event".to_string());
    }
    Ok(EncryptedEvent {
        workspace: bytes[1..33].try_into().unwrap(),
        timestamp: u64::from_be_bytes(bytes[33..41].try_into().unwrap()),
        dependency_id: bytes[41..73].try_into().unwrap(),
        key_id: bytes[73..105].try_into().unwrap(),
    })
}

fn encode_dep_event(event: DepEvent) -> Vec<u8> {
    let mut out = Vec::with_capacity(65);
    out.push(TYPE_DEP_EVENT);
    out.extend_from_slice(&event.workspace);
    out.extend_from_slice(&event.event_id);
    out
}

fn decode_dep_event(bytes: &[u8]) -> Result<DepEvent, String> {
    if bytes.len() != 65 || bytes[0] != TYPE_DEP_EVENT {
        return Err("invalid dependency event".to_string());
    }
    Ok(DepEvent {
        workspace: bytes[1..33].try_into().unwrap(),
        event_id: bytes[33..65].try_into().unwrap(),
    })
}

fn encode_key_offer(key: KeyOffer) -> Vec<u8> {
    let mut out = Vec::with_capacity(65);
    out.push(TYPE_KEY_OFFER);
    out.extend_from_slice(&key.workspace);
    out.extend_from_slice(&key.key_id);
    out
}

fn decode_key_offer(bytes: &[u8]) -> Result<KeyOffer, String> {
    if bytes.len() != 65 || bytes[0] != TYPE_KEY_OFFER {
        return Err("invalid key offer".to_string());
    }
    Ok(KeyOffer {
        workspace: bytes[1..33].try_into().unwrap(),
        key_id: bytes[33..65].try_into().unwrap(),
    })
}

fn require_scope(fact: &Fact, expected: &FactScope) -> Result<(), String> {
    if &fact.scope == expected {
        Ok(())
    } else {
        Err("sync context test fact scope mismatch".to_string())
    }
}

fn id(value: u8) -> FactId {
    [value; 32]
}
