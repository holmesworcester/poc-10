//! Poc-10 local history node secret projector.
//!
//! POLICY. A local_history_node_secret is admitted iff:
//!   1. STRUCTURAL. The fact is local-only and the history-node secret payload
//!      decodes.
//!   2. CONTEXT. Projection waits for the removal frontier, source secret, and
//!      optional tombstone source, then validates tree addressing.
//!   3. MATERIALIZE. Publish exact/source/coverage offers and write the local
//!      history-node secret row.

mod secret_path;

use crate::core::facts::{Fact, FactScope};
use crate::core::intents::AtomicIntent;
use crate::core::projection::{
    project_typed, ProjectionContext, ProjectionOutput, Projector, TypedProjector,
};
use crate::protocol::matchers as history_matchers;

use super::rows::local_history_node_secret_row;
use secret_path::{
    validate_child_addressing, validate_frontier, validate_source, validate_tombstone, SourceKind,
};

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
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        project_typed::<super::Codec, _>(self, fact, projection_context)
    }
}

impl TypedProjector<super::Codec> for LocalHistoryNodeSecretProjector {
    fn project_typed(
        &self,
        fact: &Fact,
        node: super::fact::LocalHistoryNodeSecretFact,
        projection_context: &ProjectionContext,
    ) -> Result<ProjectionOutput, String> {
        // 1. Structural.
        if fact.scope != FactScope::Local {
            return Err("local history node secret fact must have FactScope::Local".to_string());
        }
        let workspace_scope = crate::protocol::matchers::workspace_scope(node.workspace_id);

        // 2. Context and path validation.
        let frontier_need = crate::protocol::matchers::exact_fact_need(
            fact.id,
            workspace_scope.clone(),
            node.removal_frontier_id,
        );
        let source_need = history_matchers::source_secret_need(fact.id, node.source_secret_id);
        let tombstone_need = if node.tombstone_node_id == [0; 32] {
            None
        } else {
            Some(history_matchers::source_secret_need(
                fact.id,
                node.tombstone_node_id,
            ))
        };

        let mut waiting = ProjectionOutput::new()
            .need(frontier_need.clone())
            .need(source_need.clone());
        if let Some(need) = &tombstone_need {
            waiting = waiting.need(need.clone());
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

        validate_frontier(frontier_fact, &node)?;
        let source = validate_source(source_fact, &node)?;
        match source {
            SourceKind::HistoryNode(source_node) => {
                validate_child_addressing(&source_node, &node)?;
                if node.tombstone_node_id != [0; 32]
                    && node.tombstone_node_id != node.source_secret_id
                {
                    return Err(
                        "local history node tombstone must retire its source path node".to_string(),
                    );
                }
            }
            SourceKind::Root => {
                if node.tombstone_node_id != [0; 32] {
                    return Err(
                        "local history node cannot tombstone without a history source".to_string(),
                    );
                }
            }
        }
        if let Some(tombstone) = tombstone_fact {
            validate_tombstone(tombstone, &node)?;
        }

        let end_minute = node
            .range_start
            .checked_add(node.range_width - 1)
            .ok_or_else(|| "local history node range end overflow".to_string())?;

        // 3. Materialize.
        Ok(waiting
            .offer(crate::protocol::matchers::exact_fact_offer(
                fact.id,
                FactScope::Local,
                fact.id,
            ))
            .offer(history_matchers::source_secret_offer(fact.id, fact.id))
            .offer(crate::protocol::matchers::secret_offer(
                fact.id,
                workspace_scope,
                node.workspace_id,
                node.removal_frontier_id,
                node.range_start,
                end_minute,
                prefix_bytes(node.bit_depth)?,
                node.fact_id_prefix,
            ))
            .intent(
                AtomicIntent::PutRow(local_history_node_secret_row(fact.id, &node)?).into_intent(),
            ))
    }
}

fn prefix_bytes(bit_depth: u16) -> Result<u8, String> {
    if bit_depth % 8 != 0 {
        return Err(
            "local history node prefix depth must be byte-aligned for coverage".to_string(),
        );
    }
    u8::try_from(bit_depth / 8)
        .map_err(|_| "local history node prefix depth is too large".to_string())
}

#[cfg(test)]
mod projector_tests {
    use crate as topo;

    use topo::core::facts::{Fact, FactScope, ScopeKind};
    use topo::core::intents::AtomicIntent;
    use topo::core::projection::{MatchedContext, ProjectionContext, Projector};
    use topo::protocol::facts::encryption::fact::LocalKeySecretFact;
    use topo::protocol::facts::encryption::layout as encryption_layout;
    use topo::protocol::facts::encryption::local_history_node_secret::fact::{
        LocalHistoryNodeSecretFact, NODE_SECRET_BYTES, TRIE_LEAF_BIT_DEPTH,
    };
    use topo::protocol::facts::encryption::local_history_node_secret::{layout, project, rows};
    use topo::protocol::facts::encryption::removal_frontier::fact::RemovalFrontierFact;
    use topo::protocol::facts::encryption::removal_frontier::layout as frontier_layout;
    use topo::protocol::matchers;
    use topo::protocol::matchers as sync_matchers;

    fn workspace_scope(workspace_id: [u8; 32]) -> FactScope {
        FactScope::Scoped {
            kind: ScopeKind::new("workspace").expect("scope kind"),
            id: workspace_id,
        }
    }

    fn minute_node_fact(
        frontier_id: [u8; 32],
        source_secret_id: [u8; 32],
    ) -> LocalHistoryNodeSecretFact {
        LocalHistoryNodeSecretFact {
            workspace_id: [1; 32],
            removal_frontier_id: frontier_id,
            source_secret_id,
            range_start: 1_700_000,
            range_width: 1,
            bit_depth: 0,
            fact_id_prefix: [0; 32],
            tombstone_node_id: [0; 32],
            node_secret: [9; NODE_SECRET_BYTES],
        }
    }

    #[test]
    fn local_history_node_secret_waits_for_frontier_and_source_then_materializes_row() {
        let frontier = frontier_fact([1; 32]);
        let root = root_secret_fact([1; 32], frontier.id);
        let node = minute_node_fact(frontier.id, root.id);
        let fact = local_history_fact(&node, 1);
        let projector = project::LocalHistoryNodeSecretProjector::new();

        let waiting = projector
            .project(&fact, &ProjectionContext::default())
            .expect("missing context waits");
        assert!(waiting.intents.is_empty());
        assert_eq!(waiting.needs.len(), 2);

        let projected = projector
            .project(
                &fact,
                &ProjectionContext::from_matches(vec![
                    frontier_match(fact.id, &node, frontier),
                    source_match(fact.id, node.source_secret_id, root),
                ]),
            )
            .expect("matched context projects history node");
        assert_eq!(projected.intents.len(), 1);
        assert!(projected
            .offers
            .iter()
            .any(|offer| offer.role == matchers::source_secret_role()));

        let row = decode_single_put_row(&projected.intents[0]);
        assert_eq!(row.workspace_id, [1; 32]);
        assert_eq!(row.removal_frontier_id, node.removal_frontier_id);
        assert_eq!(row.local_history_node_secret_id, fact.id);
        assert_eq!(row.range_start, 1_700_000);
        assert_eq!(row.range_width, 1);
        assert_eq!(row.bit_depth, 0);
        assert_eq!(row.fact_id_prefix, [0; 32]);
        assert_eq!(row.node_secret, [9; NODE_SECRET_BYTES]);
    }

    #[test]
    fn local_history_node_secret_projector_rejects_non_local_scope() {
        let frontier = frontier_fact([1; 32]);
        let root = root_secret_fact([1; 32], frontier.id);
        let node = minute_node_fact(frontier.id, root.id);
        let fact = Fact::new(
            FactScope::Global,
            1,
            layout::encode_fact(&node).expect("encode"),
        );

        let err = project::LocalHistoryNodeSecretProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect_err("non-local scope must fail");
        assert!(err.contains("Local"), "{err}");
    }

    #[test]
    fn local_history_node_secret_projector_materializes_trie_leaf_row() {
        let frontier = frontier_fact([1; 32]);
        let root = root_secret_fact([1; 32], frontier.id);
        let leaf = LocalHistoryNodeSecretFact {
            bit_depth: TRIE_LEAF_BIT_DEPTH,
            fact_id_prefix: [9; 32],
            node_secret: [7; NODE_SECRET_BYTES],
            ..minute_node_fact(frontier.id, root.id)
        };
        let fact = local_history_fact(&leaf, 1);

        let projected = project::LocalHistoryNodeSecretProjector::new()
            .project(
                &fact,
                &ProjectionContext::from_matches(vec![
                    frontier_match(fact.id, &leaf, frontier),
                    source_match(fact.id, leaf.source_secret_id, root),
                ]),
            )
            .expect("project leaf");

        let row = decode_single_put_row(&projected.intents[0]);
        assert_eq!(row.bit_depth, TRIE_LEAF_BIT_DEPTH);
        assert_eq!(row.fact_id_prefix, [9; 32]);
        assert_eq!(row.node_secret, [7; NODE_SECRET_BYTES]);
    }

    #[test]
    fn local_history_node_secret_waits_for_tombstone_source_context() {
        let frontier = frontier_fact([1; 32]);
        let root = root_secret_fact([1; 32], frontier.id);
        let parent = local_history_fact(
            &LocalHistoryNodeSecretFact {
                range_start: 1_700_000,
                range_width: 2,
                ..minute_node_fact(frontier.id, root.id)
            },
            2,
        );
        let node = LocalHistoryNodeSecretFact {
            source_secret_id: parent.id,
            tombstone_node_id: [8; 32],
            ..minute_node_fact(frontier.id, parent.id)
        };
        let fact = local_history_fact(&node, 3);

        let waiting = project::LocalHistoryNodeSecretProjector::new()
            .project(
                &fact,
                &ProjectionContext::from_matches(vec![
                    frontier_match(fact.id, &node, frontier),
                    source_match(fact.id, node.source_secret_id, parent),
                ]),
            )
            .expect("missing tombstone waits");

        assert!(waiting.intents.is_empty());
        assert!(waiting
            .needs
            .iter()
            .any(|need| need.selector.as_bytes() == &[8u8; 32][..]));
    }

    fn frontier_fact(workspace_id: [u8; 32]) -> Fact {
        let frontier = RemovalFrontierFact {
            workspace_id,
            created_at_ms: 10,
            authority_admin_id: [2; 32],
            removal_fact_ids: Vec::new(),
        };
        Fact::new(
            workspace_scope(workspace_id),
            10,
            frontier_layout::encode_fact(&frontier).expect("encode frontier"),
        )
    }

    fn root_secret_fact(workspace_id: [u8; 32], frontier_id: [u8; 32]) -> Fact {
        Fact::new(
            FactScope::Local,
            10,
            encryption_layout::encode_local_key_secret(&LocalKeySecretFact {
                workspace_id,
                frontier_id,
                owner_endpoint_id: [6; 32],
                created_at_ms: 10,
                key_secret: [7; 32],
            })
            .expect("encode root"),
        )
    }

    fn local_history_fact(node: &LocalHistoryNodeSecretFact, timestamp: u64) -> Fact {
        Fact::new(
            FactScope::Local,
            timestamp,
            layout::encode_fact(node).expect("encode history node"),
        )
    }

    fn frontier_match(
        owner: [u8; 32],
        node: &LocalHistoryNodeSecretFact,
        frontier: Fact,
    ) -> MatchedContext {
        matched(
            sync_matchers::exact_fact_need(
                owner,
                workspace_scope(node.workspace_id),
                node.removal_frontier_id,
            ),
            sync_matchers::exact_fact_offer(
                frontier.id,
                workspace_scope(node.workspace_id),
                frontier.id,
            ),
            frontier,
        )
    }

    fn source_match(owner: [u8; 32], source_secret_id: [u8; 32], source: Fact) -> MatchedContext {
        matched(
            matchers::source_secret_need(owner, source_secret_id),
            matchers::source_secret_offer(source.id, source.id),
            source,
        )
    }

    fn matched(
        need: topo::core::context::ContextNeed,
        offer: topo::core::context::ContextOffer,
        payload: Fact,
    ) -> MatchedContext {
        MatchedContext {
            need,
            offer,
            payload,
        }
    }

    fn decode_single_put_row(
        intent: &topo::core::intents::Intent,
    ) -> rows::LocalHistoryNodeSecretRow {
        match AtomicIntent::from_intent(intent, &[rows::LOCAL_HISTORY_NODE_SECRET_ROWS])
            .expect("row intent")
        {
            AtomicIntent::PutRow(row) => {
                rows::decode_local_history_node_secret_row(&row.key, &row.value)
                    .expect("decode row")
            }
            AtomicIntent::DeleteRow(_) => panic!("expected put row"),
        }
    }
}
