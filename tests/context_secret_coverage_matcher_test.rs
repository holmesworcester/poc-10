use topo::core::context::{ContextNeed, ContextOffer, Role, Selector};
use topo::core::facts::{Fact, FactId, FactScope, ScopeKind};
use topo::core::intents::AtomicIntent;
use topo::core::matchers::{ContextMatch, ContextMatcher};
use topo::core::projection::{ProjectionContext, ProjectionOutput, Projector};
use topo::core::store::{TableName, TableRow};
use topo::core::wake_loop::WakeLoop;

#[test]
fn secret_coverage_matcher_handles_root_internal_leaf_ranges() {
    let matcher = SecretCoverageMatcher::new();
    let workspace = [7; 32];
    let scope = workspace_scope(workspace);
    let need = secret_need([1; 32], scope.clone(), workspace, 42);
    let root_offer = secret_offer([2; 32], scope.clone(), workspace, 0, 99);
    let exact_leaf_offer = secret_offer([3; 32], scope.clone(), workspace, 42, 42);
    let wrong_workspace_offer = secret_offer([4; 32], scope.clone(), [8; 32], 0, 99);
    let after_leaf_offer = secret_offer([5; 32], scope, workspace, 43, 99);

    let matches = matcher.match_new_need(
        &need,
        &[
            root_offer.clone(),
            exact_leaf_offer.clone(),
            wrong_workspace_offer,
            after_leaf_offer,
        ],
    );

    assert_eq!(matches.len(), 2);
    assert!(matches
        .iter()
        .any(|matched| matched.payload_ref == root_offer.payload_ref));
    assert!(matches
        .iter()
        .any(|matched| matched.payload_ref == exact_leaf_offer.payload_ref));
}

#[test]
fn secret_coverage_offer_wakes_message_without_event_dependency() {
    let matcher = SecretCoverageMatcher::new();
    let workspace = [9; 32];
    let projector = SecretProjection::new(workspace);
    let message = message_fact(workspace, 42);
    let root_key = key_fact(workspace, 0, 99, 1);
    let internal_key = key_fact(workspace, 40, 50, 2);
    let mut bus = WakeLoop::new();

    bus.submit_fact(message.clone());
    let waiting = bus
        .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
        .expect("message waits for secret coverage");
    assert_eq!(waiting.projections, 1);
    assert_eq!(waiting.intents, 0);
    assert_eq!(bus.context(&message.id).unwrap().needs.len(), 1);

    bus.submit_fact(root_key);
    bus.submit_fact(internal_key);
    let opened = bus
        .drain(&projector, &[&matcher as &dyn ContextMatcher], 10)
        .expect("secret coverage opens message");

    assert_eq!(opened.projections, 3);
    assert_eq!(opened.wakes, 1);
    assert_eq!(opened.intents, 1);
    assert!(bus.context(&message.id).is_none());
    assert_eq!(bus.intents().len(), 1);
    assert_eq!(bus.intents()[0].kind.as_str(), "put_row");
}

struct SecretCoverageMatcher {
    role: Role,
}

impl SecretCoverageMatcher {
    fn new() -> Self {
        Self {
            role: secret_role(),
        }
    }
}

impl ContextMatcher for SecretCoverageMatcher {
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
            .filter_map(|offer| secret_coverage_match(need, offer))
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
            .filter_map(|need| secret_coverage_match(need, offer))
            .collect()
    }
}

fn secret_coverage_match(need: &ContextNeed, offer: &ContextOffer) -> Option<ContextMatch> {
    if need.role != offer.role || need.scope != offer.scope {
        return None;
    }
    let (need_workspace, coord) = decode_secret_need_selector(&need.selector)?;
    let (offer_workspace, start, end) = decode_secret_offer_selector(&offer.selector)?;
    if need_workspace == offer_workspace && start <= coord && coord <= end {
        Some(ContextMatch {
            need_owner: need.owner,
            offer_owner: offer.owner,
            payload_ref: offer.payload_ref,
        })
    } else {
        None
    }
}

struct SecretProjection {
    role: Role,
    workspace: FactId,
}

impl SecretProjection {
    fn new(workspace: FactId) -> Self {
        Self {
            role: secret_role(),
            workspace,
        }
    }
}

impl Projector for SecretProjection {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        match fact.bytes.first().copied() {
            Some(1) => {
                let coord = decode_message(&fact.bytes)?;
                if context.offers().is_empty() {
                    Ok(ProjectionOutput::new().need(secret_need(
                        fact.id,
                        fact.scope.clone(),
                        self.workspace,
                        coord,
                    )))
                } else {
                    Ok(ProjectionOutput::new().intent(
                        AtomicIntent::PutRow(TableRow {
                            table: TableName::new("secret_projection_rows"),
                            key: fact.id.to_vec(),
                            value: coord.to_be_bytes().to_vec(),
                        })
                        .into_intent(),
                    ))
                }
            }
            Some(2) => {
                let (start, end) = decode_key_range(&fact.bytes)?;
                Ok(ProjectionOutput::new().offer(ContextOffer {
                    owner: fact.id,
                    role: self.role.clone(),
                    scope: fact.scope.clone(),
                    selector: secret_offer_selector(self.workspace, start, end),
                    payload_ref: fact.id,
                }))
            }
            _ => Err("unknown secret projection fact".to_string()),
        }
    }
}

fn secret_need(owner: FactId, scope: FactScope, workspace: FactId, coord: u64) -> ContextNeed {
    ContextNeed {
        owner,
        role: secret_role(),
        scope,
        selector: secret_need_selector(workspace, coord),
    }
}

fn secret_offer(
    owner: FactId,
    scope: FactScope,
    workspace: FactId,
    start: u64,
    end: u64,
) -> ContextOffer {
    ContextOffer {
        owner,
        role: secret_role(),
        scope,
        selector: secret_offer_selector(workspace, start, end),
        payload_ref: owner,
    }
}

fn message_fact(workspace: FactId, coord: u64) -> Fact {
    let mut bytes = vec![1];
    bytes.extend_from_slice(&coord.to_be_bytes());
    Fact::new(workspace_scope(workspace), coord, bytes)
}

fn key_fact(workspace: FactId, start: u64, end: u64, salt: u8) -> Fact {
    let mut bytes = vec![2];
    bytes.extend_from_slice(&start.to_be_bytes());
    bytes.extend_from_slice(&end.to_be_bytes());
    bytes.push(salt);
    Fact::new(workspace_scope(workspace), start, bytes)
}

fn secret_role() -> Role {
    Role::new("secret_coverage").unwrap()
}

fn workspace_scope(workspace: FactId) -> FactScope {
    FactScope::Scoped {
        kind: ScopeKind::new("workspace").unwrap(),
        id: workspace,
    }
}

fn secret_need_selector(workspace: FactId, coord: u64) -> Selector {
    let mut bytes = workspace.to_vec();
    bytes.extend_from_slice(&coord.to_be_bytes());
    Selector::from_bytes(bytes)
}

fn secret_offer_selector(workspace: FactId, start: u64, end: u64) -> Selector {
    let mut bytes = workspace.to_vec();
    bytes.extend_from_slice(&start.to_be_bytes());
    bytes.extend_from_slice(&end.to_be_bytes());
    Selector::from_bytes(bytes)
}

fn decode_secret_need_selector(selector: &Selector) -> Option<(FactId, u64)> {
    let bytes = selector.as_bytes();
    if bytes.len() != 40 {
        return None;
    }
    let workspace = bytes[..32].try_into().ok()?;
    let coord = u64::from_be_bytes(bytes[32..40].try_into().ok()?);
    Some((workspace, coord))
}

fn decode_secret_offer_selector(selector: &Selector) -> Option<(FactId, u64, u64)> {
    let bytes = selector.as_bytes();
    if bytes.len() != 48 {
        return None;
    }
    let workspace = bytes[..32].try_into().ok()?;
    let start = u64::from_be_bytes(bytes[32..40].try_into().ok()?);
    let end = u64::from_be_bytes(bytes[40..48].try_into().ok()?);
    Some((workspace, start, end))
}

fn decode_message(bytes: &[u8]) -> Result<u64, String> {
    if bytes.len() != 9 {
        return Err("invalid message fact length".to_string());
    }
    Ok(u64::from_be_bytes(bytes[1..9].try_into().unwrap()))
}

fn decode_key_range(bytes: &[u8]) -> Result<(u64, u64), String> {
    if bytes.len() != 18 {
        return Err("invalid key range fact length".to_string());
    }
    let start = u64::from_be_bytes(bytes[1..9].try_into().unwrap());
    let end = u64::from_be_bytes(bytes[9..17].try_into().unwrap());
    Ok((start, end))
}
