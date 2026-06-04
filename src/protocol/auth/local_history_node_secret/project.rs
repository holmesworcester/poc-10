//! Local history-node secret projector plus the secret-coverage scheme.
//!
//! POLICY. A local history-node secret is admitted iff it is local-scoped, ties
//! cleanly to its frontier and source chain, and obeys parent/child addressing.
//! Projection publishes wrap-source and secret-coverage offers while live, and
//! self-purges when retirement context names this node. A tombstoning node
//! publishes retirement context for the source path node it replaces.
//!
//! This module also owns the secret-coverage coordinate scheme: core only sees
//! byte ranges, so the time/leaf-prefix layout for encrypted-message secret
//! coverage lives here. Content-message projection consumes these helpers.

use crate::core::context::{ContextKey, ContextNeed, ContextOffer, Role};
use crate::core::facts::{Fact, FactId, FactScope};
use crate::core::pipeline::{
    project_authenticated, AuthenticatedFact, AuthenticatedProjector, ProjectionContext,
    ProjectionOutput, Projector,
};
use crate::protocol::auth::key_wrap::project::{
    history_node_wrap_source_offers, require_local_scope,
};
use crate::protocol::auth::local_key_secret;
use crate::protocol::auth::local_secret_retirement;
use crate::protocol::auth::removal_frontier;

use super::fact::{
    mask_prefix_to_depth, LocalHistoryNodeSecretFact, TIME_TREE_BIT_DEPTH, TRIE_LEAF_BIT_DEPTH,
};

// ---------------------------------------------------------------------------
// Secret coverage coordinate scheme.
// ---------------------------------------------------------------------------

const COVERAGE_ROLE: &str = "secret_coverage";

pub fn secret_role() -> Role {
    Role::expect(COVERAGE_ROLE)
}

pub fn secret_need(
    owner: FactId,
    scope: FactScope,
    workspace_id: FactId,
    frontier_id: FactId,
    minute: u64,
    leaf_id: FactId,
) -> ContextNeed {
    let key = secret_need_key(workspace_id, frontier_id, minute, leaf_id);
    ContextNeed::range(
        owner,
        secret_role(),
        scope,
        key.as_bytes().to_vec(),
        key.as_bytes().to_vec(),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn secret_offer(
    owner: FactId,
    scope: FactScope,
    workspace_id: FactId,
    frontier_id: FactId,
    start_minute: u64,
    end_minute: u64,
    prefix_bytes: u8,
    leaf_prefix: FactId,
) -> ContextOffer {
    let prefix_bytes = prefix_bytes.min(32);
    let start = secret_range_key(
        workspace_id,
        frontier_id,
        start_minute,
        prefix_bound(leaf_prefix, prefix_bytes, BoundSide::Low),
    );
    let end = secret_range_key(
        workspace_id,
        frontier_id,
        end_minute,
        prefix_bound(leaf_prefix, prefix_bytes, BoundSide::High),
    );
    ContextOffer::range(owner, secret_role(), scope, start, end)
}

pub fn secret_need_key(
    workspace_id: FactId,
    frontier_id: FactId,
    minute: u64,
    leaf_id: FactId,
) -> ContextKey {
    ContextKey::from_bytes(secret_range_key(workspace_id, frontier_id, minute, leaf_id))
}

fn secret_range_key(
    workspace_id: FactId,
    frontier_id: FactId,
    minute: u64,
    leaf_id: FactId,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(105);
    bytes.push(1);
    bytes.extend_from_slice(&workspace_id);
    bytes.extend_from_slice(&frontier_id);
    bytes.extend_from_slice(&minute.to_be_bytes());
    bytes.extend_from_slice(&leaf_id);
    bytes
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoundSide {
    Low,
    High,
}

fn prefix_bound(mut prefix: FactId, prefix_bytes: u8, side: BoundSide) -> FactId {
    let prefix_bytes = usize::from(prefix_bytes.min(32));
    match side {
        BoundSide::Low => prefix[prefix_bytes..].fill(0),
        BoundSide::High => prefix[prefix_bytes..].fill(0xff),
    }
    prefix
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretNeedKey {
    pub workspace_id: FactId,
    pub frontier_id: FactId,
    pub minute: u64,
    pub leaf_id: FactId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretOfferRange {
    pub workspace_id: FactId,
    pub frontier_id: FactId,
    pub start_minute: u64,
    pub end_minute: u64,
    pub leaf_prefix: FactId,
    pub prefix_bytes: u8,
}

pub fn decode_secret_need_key(key: &ContextKey) -> Option<SecretNeedKey> {
    let bytes = key.as_bytes();
    if bytes.len() != 105 || bytes[0] != 1 {
        return None;
    }
    Some(SecretNeedKey {
        workspace_id: bytes[1..33].try_into().ok()?,
        frontier_id: bytes[33..65].try_into().ok()?,
        minute: u64::from_be_bytes(bytes[65..73].try_into().ok()?),
        leaf_id: bytes[73..105].try_into().ok()?,
    })
}

fn decode_secret_offer_range(offer: &ContextOffer) -> Option<SecretOfferRange> {
    let start = decode_secret_need_key(&offer.start_key)?;
    let end = decode_secret_need_key(&offer.end_key)?;
    if start.workspace_id != end.workspace_id
        || start.frontier_id != end.frontier_id
        || start.minute > end.minute
    {
        return None;
    }
    let prefix_bytes = common_prefix_bytes(&start.leaf_id, &end.leaf_id);
    Some(SecretOfferRange {
        workspace_id: start.workspace_id,
        frontier_id: start.frontier_id,
        start_minute: start.minute,
        end_minute: end.minute,
        leaf_prefix: start.leaf_id,
        prefix_bytes,
    })
}

fn common_prefix_bytes(left: &FactId, right: &FactId) -> u8 {
    left.iter()
        .zip(right.iter())
        .take_while(|(left, right)| left == right)
        .count()
        .min(32) as u8
}

pub fn secret_coverage_offer_valid_for_need(need: &ContextNeed, offer: &ContextOffer) -> bool {
    if need.role != offer.role || need.scope != offer.scope {
        return false;
    }
    if need.start_key != need.end_key {
        return false;
    }
    let Some(need) = decode_secret_need_key(&need.start_key) else {
        return false;
    };
    let Some(offer_range) = decode_secret_offer_range(offer) else {
        return false;
    };
    need.workspace_id == offer_range.workspace_id
        && need.frontier_id == offer_range.frontier_id
        && need.minute >= offer_range.start_minute
        && need.minute <= offer_range.end_minute
        && prefix_matches(
            &need.leaf_id,
            &offer_range.leaf_prefix,
            offer_range.prefix_bytes,
        )
}

fn prefix_matches(value: &FactId, prefix: &FactId, prefix_bytes: u8) -> bool {
    let prefix_bytes = usize::from(prefix_bytes.min(32));
    value[..prefix_bytes] == prefix[..prefix_bytes]
}

// ---------------------------------------------------------------------------
// Local history-node secret projector.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
pub struct LocalHistoryNodeSecretProjector;

impl LocalHistoryNodeSecretProjector {
    pub fn new() -> Self {
        Self
    }
}

impl Projector for LocalHistoryNodeSecretProjector {
    fn project(
        &self,
        fact: &Fact,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_authenticated::<super::authenticate::LocalHistoryNodeSecretAuthenticator, _>(
            self, fact, context,
        )
    }
}

impl AuthenticatedProjector<super::authenticate::LocalHistoryNodeSecretAuthenticator>
    for LocalHistoryNodeSecretProjector
{
    fn project_authenticated(
        &self,
        authenticated: AuthenticatedFact<'_, LocalHistoryNodeSecretFact>,
        context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        let (fact, node) = authenticated.into_parts();
        project_local_history_node_secret(fact, context, node)
    }
}

fn project_local_history_node_secret(
    fact: &Fact,
    projection_context: &ProjectionContext,
    node: LocalHistoryNodeSecretFact,
) -> Result<ProjectionOutput, String> {
    // 1. Structural.
    let scope = crate::protocol::auth::workspace::scope(node.workspace_id);
    require_local_scope(fact)?;
    // 2. Context and path validation.
    let frontier_need = ContextNeed::range(
        fact.id,
        "auth_removal_frontier",
        scope.clone(),
        node.frontier_id,
        node.frontier_id,
    );
    let source_need = ContextNeed::range(
        fact.id,
        "local_secret_source",
        FactScope::Local,
        node.source_secret_id,
        node.source_secret_id,
    );
    let tombstone_need = if node.tombstone_node_id == [0; 32] {
        None
    } else {
        Some(ContextNeed::range(
            fact.id,
            "local_secret_source",
            FactScope::Local,
            node.tombstone_node_id,
            node.tombstone_node_id,
        ))
    };
    let retirement_need = local_secret_retirement::secret_retired_need(fact.id, fact.id);
    let mut waiting = ProjectionOutput::new()
        .need(frontier_need.clone())
        .need(source_need.clone())
        .need(retirement_need.clone());
    if let Some(need) = &tombstone_need {
        waiting = waiting.need(need.clone());
    }
    if let Some(retirement_fact) = projection_context.payload_for(&retirement_need) {
        validate_history_retirement(retirement_fact, fact.id, &node)?;
        return Ok(ProjectionOutput::new().purge_self(fact.id));
    }

    let Some(frontier_fact) = projection_context.payload_for(&frontier_need) else {
        return Ok(waiting);
    };
    let Some(source_fact) = projection_context.payload_for(&source_need) else {
        return Ok(waiting);
    };
    let tombstone_fact = if let Some(need) = &tombstone_need {
        let Some(payload) = projection_context.payload_for(need) else {
            return Ok(waiting);
        };
        Some(payload)
    } else {
        None
    };

    validate_history_frontier(frontier_fact, &node)?;
    let source = validate_history_source(source_fact, &node)?;
    match source {
        HistorySourceKind::Root => {
            if node.tombstone_node_id != [0; 32] {
                return Err(
                    "local history node cannot tombstone without a history source".to_string(),
                );
            }
        }
        HistorySourceKind::HistoryNode(source_node) => {
            validate_history_child_addressing(&source_node, &node)?;
            if node.tombstone_node_id != [0; 32] && node.tombstone_node_id != node.source_secret_id
            {
                return Err(
                    "local history node tombstone must retire its source path node".to_string(),
                );
            }
        }
    }
    if let Some(tombstone) = tombstone_fact {
        validate_history_tombstone(tombstone, &node)?;
    }

    let end_minute = node
        .range_start
        .checked_add(node.range_width - 1)
        .ok_or_else(|| "history node range end overflow".to_string())?;
    if !node.bit_depth.is_multiple_of(8) {
        return Err(
            "content-message history coverage only accepts byte-aligned prefixes".to_string(),
        );
    }
    let prefix_bytes = (node.bit_depth / 8)
        .try_into()
        .map_err(|_| "history node prefix byte width overflow".to_string())?;
    // 3. Materialize: publish wrap-source, source, and coverage offers.
    let mut output = waiting;
    for offer in history_node_wrap_source_offers(
        fact.id,
        scope.clone(),
        node.workspace_id,
        node.frontier_id,
        node.owner_endpoint_id,
        node.range_start,
        node.range_width,
        node.bit_depth,
        node.fact_id_prefix,
    ) {
        output = output.offer(offer);
    }
    if node.tombstone_node_id != [0; 32] {
        output = output.offer(local_secret_retirement::secret_retired_offer(
            fact.id,
            node.tombstone_node_id,
        ));
    }
    Ok(output
        .offer(ContextOffer::range(
            fact.id,
            "local_secret_source",
            FactScope::Local,
            fact.id,
            fact.id,
        ))
        .offer(secret_offer(
            fact.id,
            scope,
            node.workspace_id,
            node.frontier_id,
            node.range_start,
            end_minute,
            prefix_bytes,
            node.fact_id_prefix,
        )))
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HistorySourceKind {
    Root,
    HistoryNode(HistoryNodeAddress),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HistoryNodeAddress {
    range_start: u64,
    range_width: u64,
    bit_depth: u16,
    fact_id_prefix: [u8; 32],
}

fn validate_history_frontier(
    frontier_fact: &Fact,
    node: &LocalHistoryNodeSecretFact,
) -> Result<(), String> {
    if frontier_fact.id != node.frontier_id {
        return Err("local history node frontier context payload id mismatch".to_string());
    }
    let frontier = removal_frontier::decode_fact_payload(&frontier_fact.bytes).map_err(|_| {
        "local history node frontier context must be a removal frontier".to_string()
    })?;
    if frontier.workspace_id != node.workspace_id {
        return Err("local history node frontier workspace mismatch".to_string());
    }
    if frontier.owner_endpoint_id != node.owner_endpoint_id {
        return Err("local history node frontier owner mismatch".to_string());
    }
    Ok(())
}

fn validate_history_source(
    source_fact: &Fact,
    node: &LocalHistoryNodeSecretFact,
) -> Result<HistorySourceKind, String> {
    if source_fact.id != node.source_secret_id {
        return Err("local history node source context payload id mismatch".to_string());
    }
    if let Ok(source) = local_key_secret::decode_fact_payload(&source_fact.bytes) {
        if source.workspace_id != node.workspace_id
            || source.frontier_id != node.frontier_id
            || source.owner_endpoint_id != node.owner_endpoint_id
        {
            return Err(
                "local history node source workspace, frontier, or owner mismatch".to_string(),
            );
        }
        return Ok(HistorySourceKind::Root);
    }
    if let Ok(source) = super::decode_fact_payload(&source_fact.bytes) {
        if source.workspace_id != node.workspace_id
            || source.frontier_id != node.frontier_id
            || source.owner_endpoint_id != node.owner_endpoint_id
        {
            return Err(
                "local history node source workspace, frontier, or owner mismatch".to_string(),
            );
        }
        return Ok(HistorySourceKind::HistoryNode(HistoryNodeAddress {
            range_start: source.range_start,
            range_width: source.range_width,
            bit_depth: source.bit_depth,
            fact_id_prefix: source.fact_id_prefix,
        }));
    }
    Err("local history node source context is not key material".to_string())
}

fn validate_history_retirement(
    retirement_fact: &Fact,
    target_id: FactId,
    node: &LocalHistoryNodeSecretFact,
) -> Result<(), String> {
    if retirement_fact.scope != FactScope::Local {
        return Err("local history node retirement context must be local".to_string());
    }
    if let Ok(retirement) = local_secret_retirement::decode_fact_payload(retirement_fact.body()) {
        if retirement.workspace_id != node.workspace_id {
            return Err("local history node retirement workspace mismatch".to_string());
        }
        if retirement.target_secret_id != target_id {
            return Err("local history node retirement target mismatch".to_string());
        }
        return Ok(());
    }

    let tombstone = super::decode_fact_payload(retirement_fact.body()).map_err(|_| {
        "local history node retirement context is not a retirement or history node".to_string()
    })?;
    if tombstone.workspace_id != node.workspace_id
        || tombstone.frontier_id != node.frontier_id
        || tombstone.owner_endpoint_id != node.owner_endpoint_id
    {
        return Err("local history node retirement lineage mismatch".to_string());
    }
    if tombstone.tombstone_node_id != target_id {
        return Err("local history node retirement target mismatch".to_string());
    }
    Ok(())
}

fn validate_history_tombstone(
    tombstone_fact: &Fact,
    node: &LocalHistoryNodeSecretFact,
) -> Result<(), String> {
    if tombstone_fact.id != node.tombstone_node_id {
        return Err("local history node tombstone context payload id mismatch".to_string());
    }
    let tombstone = super::decode_fact_payload(&tombstone_fact.bytes)
        .map_err(|_| "local history node tombstone context is not a history node".to_string())?;
    if tombstone.workspace_id != node.workspace_id
        || tombstone.frontier_id != node.frontier_id
        || tombstone.owner_endpoint_id != node.owner_endpoint_id
    {
        return Err(
            "local history node tombstone workspace, frontier, or owner mismatch".to_string(),
        );
    }
    if tombstone.range_start == node.range_start
        && tombstone.range_width == node.range_width
        && tombstone.bit_depth == node.bit_depth
        && tombstone.fact_id_prefix == node.fact_id_prefix
    {
        return Err("local history node cannot tombstone its own coordinate".to_string());
    }
    Ok(())
}

fn validate_history_child_addressing(
    source: &HistoryNodeAddress,
    node: &LocalHistoryNodeSecretFact,
) -> Result<(), String> {
    if node.tombstone_node_id != [0; 32] {
        return Ok(());
    }
    if node.bit_depth > TIME_TREE_BIT_DEPTH {
        if source.range_start != node.range_start {
            return Err(
                "local history node trie child must share its parent's range_start".to_string(),
            );
        }
        if node.bit_depth <= source.bit_depth {
            return Err(
                "local history node trie child bit_depth must exceed its parent's".to_string(),
            );
        }
        if source.bit_depth >= TRIE_LEAF_BIT_DEPTH {
            return Err("local history node leaf cannot have children".to_string());
        }
        if mask_prefix_to_depth(node.fact_id_prefix, source.bit_depth) != source.fact_id_prefix {
            return Err(
                "local history node trie child prefix must extend its parent's prefix".to_string(),
            );
        }
        return Ok(());
    }

    if source.bit_depth != TIME_TREE_BIT_DEPTH {
        return Err(
            "local history node time-tree child cannot descend from a trie node".to_string(),
        );
    }
    if source.range_width <= node.range_width {
        return Err(
            "local history node time-tree child must have a strictly smaller range_width"
                .to_string(),
        );
    }
    let parent_end = source
        .range_start
        .checked_add(source.range_width)
        .ok_or_else(|| "local history node parent range overflow".to_string())?;
    let child_end = node
        .range_start
        .checked_add(node.range_width)
        .ok_or_else(|| "local history node child range overflow".to_string())?;
    if node.range_start < source.range_start || child_end > parent_end {
        return Err(
            "local history node time-tree child range is outside its parent's range".to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use crate::protocol::auth::workspace::scope;

    #[test]
    fn secret_coverage_validates_time_range_and_leaf_prefix() {
        let workspace = [1; 32];
        let frontier = [2; 32];
        let scope = scope(workspace);
        let mut prefix = [0; 32];
        prefix[0] = 0b1010_1111;
        let mut leaf = [0; 32];
        leaf[0] = 0b1010_1111;
        let need = secret_need([3; 32], scope.clone(), workspace, frontier, 42, leaf);
        let offer = secret_offer([4; 32], scope, workspace, frontier, 40, 50, 1, prefix);

        assert!(secret_coverage_offer_valid_for_need(&need, &offer));
    }

    #[test]
    fn secret_coverage_rejects_wrong_prefix() {
        let workspace = [1; 32];
        let frontier = [2; 32];
        let scope = scope(workspace);
        let mut prefix = [0; 32];
        prefix[0] = 0b1111_0000;
        let mut leaf = [0; 32];
        leaf[0] = 0b1010_1111;
        let need = secret_need([3; 32], scope.clone(), workspace, frontier, 42, leaf);
        let offer = secret_offer([4; 32], scope, workspace, frontier, 40, 50, 1, prefix);

        assert!(!secret_coverage_offer_valid_for_need(&need, &offer));
    }

    #[test]
    fn secret_coverage_rejects_inverted_offer_range() {
        let workspace = [1; 32];
        let frontier = [2; 32];
        let scope = scope(workspace);
        let need = secret_need([3; 32], scope.clone(), workspace, frontier, 42, [9; 32]);
        let offer = secret_offer([4; 32], scope, workspace, frontier, 50, 40, 0, [0; 32]);

        assert!(!secret_coverage_offer_valid_for_need(&need, &offer));
    }
}
