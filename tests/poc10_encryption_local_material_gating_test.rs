use topo::core::facts::{Fact, FactScope};
use topo::core::projectors::{MatchedContext, ProjectionContext, Projector};
use topo::protocol::encryption::local_history_node_secret::fact::LocalHistoryNodeSecretFact;
use topo::protocol::encryption::local_history_node_secret::layout as local_history_layout;
use topo::protocol::encryption::local_history_node_secret::project::LocalHistoryNodeSecretProjector;
use topo::protocol::encryption::local_key_secret::fact::LocalKeySecretFact;
use topo::protocol::encryption::local_key_secret::layout as local_key_secret_layout;
use topo::protocol::encryption::local_key_secret::project::LocalKeySecretProjector;
use topo::protocol::encryption::removal_frontier::fact::RemovalFrontierFact;
use topo::protocol::encryption::removal_frontier::layout as removal_frontier_layout;

#[test]
fn local_key_secret_waits_for_frontier_then_offers_root_material() {
    let workspace = [1; 32];
    let owner = [2; 32];
    let frontier = frontier_fact(workspace, owner, 10);
    let root = local_key_secret_fact(workspace, frontier.id, owner, 11);
    let projector = LocalKeySecretProjector::new();

    let waiting = projector
        .project(&root, &ProjectionContext::default())
        .expect("missing frontier waits");
    assert!(waiting.effects.intents.is_empty());
    assert!(waiting.offers.is_empty());
    assert_eq!(waiting.needs.len(), 1);
    assert_eq!(waiting.needs[0].role, "encryption_removal_frontier");

    let projected = projector
        .project(
            &root,
            &ProjectionContext::from_matches(vec![frontier_match(root.id, workspace, frontier)]),
        )
        .expect("matched frontier projects root material");
    assert!(projected
        .offers
        .iter()
        .any(|offer| offer.role == "wrap_source"));
    assert!(projected
        .offers
        .iter()
        .any(|offer| offer.role == "local_secret_source"));
    assert!(projected
        .offers
        .iter()
        .any(|offer| offer.role == "secret_coverage"));
}

#[test]
fn local_history_node_waits_for_frontier_source_and_tombstone_context() {
    let workspace = [3; 32];
    let owner = [4; 32];
    let frontier = frontier_fact(workspace, owner, 20);
    let root = local_key_secret_fact(workspace, frontier.id, owner, 21);
    let node = history_node_fact(workspace, frontier.id, owner, root.id, [0; 32], 30, 1);
    let projector = LocalHistoryNodeSecretProjector::new();

    let waiting = projector
        .project(&node, &ProjectionContext::default())
        .expect("missing context waits");
    assert!(waiting.effects.intents.is_empty());
    assert!(waiting.offers.is_empty());
    assert_eq!(waiting.needs.len(), 2);

    let projected = projector
        .project(
            &node,
            &ProjectionContext::from_matches(vec![
                frontier_match(node.id, workspace, frontier.clone()),
                source_match(node.id, root.id, root.clone()),
            ]),
        )
        .expect("matched source projects history material");
    assert!(projected
        .offers
        .iter()
        .any(|offer| offer.role == "wrap_source"));
    assert!(projected
        .offers
        .iter()
        .any(|offer| offer.role == "local_secret_source"));

    let parent = history_node_fact(workspace, frontier.id, owner, root.id, [0; 32], 30, 2);
    let tombstoning = history_node_fact(workspace, frontier.id, owner, parent.id, [9; 32], 30, 1);
    let waiting_for_tombstone = projector
        .project(
            &tombstoning,
            &ProjectionContext::from_matches(vec![
                frontier_match(tombstoning.id, workspace, frontier),
                source_match(tombstoning.id, parent.id, parent),
            ]),
        )
        .expect("missing tombstone waits");
    assert!(waiting_for_tombstone.effects.intents.is_empty());
    assert!(waiting_for_tombstone
        .needs
        .iter()
        .any(|need| need.start_key.as_bytes() == &[9u8; 32][..]));
}

fn frontier_fact(workspace_id: [u8; 32], owner_endpoint_id: [u8; 32], created_at_ms: u64) -> Fact {
    Fact::new(
        topo::protocol::identity::workspace::scope(workspace_id),
        created_at_ms,
        removal_frontier_layout::encode_removal_frontier(&RemovalFrontierFact {
            workspace_id,
            owner_endpoint_id,
            created_at_ms,
        })
        .expect("encode frontier"),
    )
}

fn local_key_secret_fact(
    workspace_id: [u8; 32],
    frontier_id: [u8; 32],
    owner_endpoint_id: [u8; 32],
    created_at_ms: u64,
) -> Fact {
    Fact::new(
        FactScope::Local,
        created_at_ms,
        local_key_secret_layout::encode_local_key_secret(&LocalKeySecretFact {
            workspace_id,
            frontier_id,
            owner_endpoint_id,
            created_at_ms,
            key_secret: [0x66; 32],
        })
        .expect("encode local root"),
    )
}

fn history_node_fact(
    workspace_id: [u8; 32],
    frontier_id: [u8; 32],
    owner_endpoint_id: [u8; 32],
    source_secret_id: [u8; 32],
    tombstone_node_id: [u8; 32],
    range_start: u64,
    range_width: u64,
) -> Fact {
    Fact::new(
        FactScope::Local,
        31,
        local_history_layout::encode_local_history_node_secret(&LocalHistoryNodeSecretFact {
            workspace_id,
            frontier_id,
            owner_endpoint_id,
            source_secret_id,
            range_start,
            range_width,
            bit_depth: 0,
            fact_id_prefix: [0; 32],
            tombstone_node_id,
            node_secret: [0x79; 32],
        })
        .expect("encode history node"),
    )
}

fn frontier_match(owner: [u8; 32], workspace_id: [u8; 32], frontier: Fact) -> MatchedContext {
    let scope = topo::protocol::identity::workspace::scope(workspace_id);
    matched(
        topo::core::context::ContextNeed::range(
            owner,
            "encryption_removal_frontier",
            scope.clone(),
            frontier.id,
            frontier.id,
        ),
        topo::core::context::ContextOffer::range(
            frontier.id,
            "encryption_removal_frontier",
            scope,
            frontier.id,
            frontier.id,
        ),
        frontier,
    )
}

fn source_match(owner: [u8; 32], source_secret_id: [u8; 32], source: Fact) -> MatchedContext {
    matched(
        topo::core::context::ContextNeed::range(
            owner,
            "local_secret_source",
            topo::core::facts::FactScope::Local,
            source_secret_id,
            source_secret_id,
        ),
        topo::core::context::ContextOffer::range(
            source.id,
            "local_secret_source",
            topo::core::facts::FactScope::Local,
            source.id,
            source.id,
        ),
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
