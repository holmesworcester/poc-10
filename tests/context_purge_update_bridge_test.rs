use topo::core::context::{ContextNeed, ContextOffer, Role, Selector};
use topo::core::facts::{Fact, FactId, FactScope, ScopeKind};
use topo::core::intents::{Intent, IntentExecution, IntentKind};
use topo::core::matchers::ContextMatcher;
use topo::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use topo::core::wake_loop::WakeLoop;
use topo::protocol::matchers::ExactSelectorMatcher;

#[test]
fn deletion_update_offer_wakes_waiting_content_fact_and_emits_purge_intent() {
    let workspace = [4; 32];
    let target = content_fact(workspace, b"content message");
    let deletion = deletion_fact(workspace, target.id);
    let primary_matcher = ExactSelectorMatcher::new(primary_role());
    let delete_matcher = ExactSelectorMatcher::new(deletion_role());
    let projector = ContentPurgeBridge::new(workspace, [77; 32]);
    let mut bus = WakeLoop::new();

    bus.submit_fact(target.clone());
    let waiting = bus
        .drain(
            &projector,
            &[
                &primary_matcher as &dyn ContextMatcher,
                &delete_matcher as &dyn ContextMatcher,
            ],
            10,
        )
        .expect("target waits for primary context");
    assert_eq!(waiting.projections, 1);
    assert_eq!(bus.context(&target.id).unwrap().needs.len(), 2);

    bus.submit_fact(deletion);
    let purged = bus
        .drain(
            &projector,
            &[
                &primary_matcher as &dyn ContextMatcher,
                &delete_matcher as &dyn ContextMatcher,
            ],
            10,
        )
        .expect("deletion wakes target");

    assert_eq!(purged.projections, 2);
    assert_eq!(purged.wakes, 1);
    assert_eq!(purged.intents, 1);
    assert!(bus.context(&target.id).is_none());
    assert_eq!(bus.intents().len(), 1);
    assert_eq!(bus.intents()[0].kind.as_str(), "purge_deleted_message");
    assert_eq!(bus.intents()[0].key, purge_key(workspace, target.id));
}

#[test]
fn repeated_deletion_offers_do_not_amplify_purge_intents() {
    let workspace = [5; 32];
    let target = content_fact(workspace, b"content message");
    let deletion_a = deletion_fact(workspace, target.id);
    let deletion_b = deletion_fact(workspace, target.id);
    let primary_matcher = ExactSelectorMatcher::new(primary_role());
    let delete_matcher = ExactSelectorMatcher::new(deletion_role());
    let projector = ContentPurgeBridge::new(workspace, [88; 32]);
    let mut bus = WakeLoop::new();

    bus.submit_fact(target.clone());
    bus.drain(
        &projector,
        &[
            &primary_matcher as &dyn ContextMatcher,
            &delete_matcher as &dyn ContextMatcher,
        ],
        10,
    )
    .expect("target waits");
    bus.submit_fact(deletion_a);
    bus.submit_fact(deletion_b);
    let purged = bus
        .drain(
            &projector,
            &[
                &primary_matcher as &dyn ContextMatcher,
                &delete_matcher as &dyn ContextMatcher,
            ],
            10,
        )
        .expect("deletions wake target once");

    assert_eq!(purged.wakes, 1);
    assert_eq!(purged.intents, 1);
    assert_eq!(bus.intents().len(), 1);
}

struct ContentPurgeBridge {
    workspace: FactId,
    missing_primary: FactId,
}

impl ContentPurgeBridge {
    fn new(workspace: FactId, missing_primary: FactId) -> Self {
        Self {
            workspace,
            missing_primary,
        }
    }
}

impl Projector for ContentPurgeBridge {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        match fact.bytes.first().copied() {
            Some(1) => {
                if context
                    .offers()
                    .iter()
                    .any(|offer| offer.role == deletion_role())
                {
                    return Ok(ProjectionOutput::new().intent(Intent::new(
                        IntentKind::new("purge_deleted_message").unwrap(),
                        IntentExecution::Deferred,
                        purge_key(self.workspace, fact.id),
                        fact.id,
                    )));
                }
                Ok(ProjectionOutput::new()
                    .need(ContextNeed {
                        owner: fact.id,
                        role: primary_role(),
                        scope: fact.scope.clone(),
                        selector: Selector::from_bytes(self.missing_primary),
                    })
                    .need(ContextNeed {
                        owner: fact.id,
                        role: deletion_role(),
                        scope: fact.scope.clone(),
                        selector: Selector::from_bytes(fact.id),
                    }))
            }
            Some(2) => {
                let target = decode_deletion_target(&fact.bytes)?;
                Ok(ProjectionOutput::new().offer(ContextOffer {
                    owner: fact.id,
                    role: deletion_role(),
                    scope: fact.scope.clone(),
                    selector: Selector::from_bytes(target),
                    payload_ref: fact.id,
                }))
            }
            _ => Err("unknown content purge bridge fact".to_string()),
        }
    }
}

fn content_fact(workspace: FactId, payload: &[u8]) -> Fact {
    let mut bytes = vec![1];
    bytes.extend_from_slice(payload);
    Fact::new(workspace_scope(workspace), 10, bytes)
}

fn deletion_fact(workspace: FactId, target: FactId) -> Fact {
    let mut bytes = vec![2];
    bytes.extend_from_slice(&target);
    Fact::new(workspace_scope(workspace), 20, bytes)
}

fn decode_deletion_target(bytes: &[u8]) -> Result<FactId, String> {
    if bytes.len() != 33 {
        return Err("invalid deletion fact length".to_string());
    }
    Ok(bytes[1..33].try_into().unwrap())
}

fn primary_role() -> Role {
    Role::new("primary_context").unwrap()
}

fn deletion_role() -> Role {
    Role::new("content_deleted").unwrap()
}

fn workspace_scope(workspace: FactId) -> FactScope {
    FactScope::Scoped {
        kind: ScopeKind::new("workspace").unwrap(),
        id: workspace,
    }
}

fn purge_key(workspace: FactId, target: FactId) -> Vec<u8> {
    let mut key = workspace.to_vec();
    key.extend_from_slice(&target);
    key
}
