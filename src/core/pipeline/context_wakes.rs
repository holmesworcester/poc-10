//! SQL helpers for waking facts after context edge additions.

use crate::core::context::{scope_key, ContextSetDelta};
use crate::core::context::{ContextNeed, ContextOffer};
use crate::core::matchers::ContextMatcher;
use crate::core::schema::{CONTEXT_EDGES, LOCAL_FACT_ADMISSIONS, PENDING_PROJECTION};
use crate::core::select;
use crate::core::store::Store;

pub(super) fn wake_context_matches_in_tx(
    store: &Store,
    delta: &ContextSetDelta,
    matchers: &[&dyn ContextMatcher],
) -> Result<usize, String> {
    let mut inserted = 0usize;
    for matcher in matchers.iter().copied() {
        for need in delta
            .added_needs
            .iter()
            .filter(|need| matcher.role() == &need.role)
        {
            inserted += wake_need_in_tx(store, matcher, need)?;
        }
        for offer in delta
            .added_offers
            .iter()
            .filter(|offer| matcher.role() == &offer.role)
        {
            inserted += wake_offer_in_tx(store, matcher, offer)?;
        }
    }
    Ok(inserted)
}

fn exact_offers_for_need_select(need: &ContextNeed) -> select::Select {
    let scope_key = scope_key(&need.scope);
    select::Select::new(
        r#"
        SELECT :need_owner AS owner
        WHERE EXISTS (
            SELECT 1
            FROM context_edges
            WHERE direction = 'offer'
              AND role = :role
              AND scope_key = :scope_key
              AND selector = :selector
        )
        "#,
        &[CONTEXT_EDGES],
        vec![
            select::Param::bytes(":need_owner", need.owner),
            select::Param::text(":role", need.role.as_str()),
            select::Param::bytes(":scope_key", scope_key),
            select::Param::bytes(":selector", need.selector.as_bytes()),
        ],
    )
}

fn exact_needs_for_offer_select(offer: &ContextOffer) -> select::Select {
    let scope_key = scope_key(&offer.scope);
    select::Select::new(
        r#"
        SELECT n.owner
        FROM context_edges n
        JOIN local_fact_admissions a ON a.fact_id = n.owner
        WHERE n.direction = 'need'
          AND n.role = :role
          AND n.scope_key = :scope_key
          AND n.selector = :selector
        ORDER BY a.received_at, n.owner
        "#,
        &[CONTEXT_EDGES, LOCAL_FACT_ADMISSIONS],
        vec![
            select::Param::text(":role", offer.role.as_str()),
            select::Param::bytes(":scope_key", scope_key),
            select::Param::bytes(":selector", offer.selector.as_bytes()),
        ],
    )
}

fn wake_need_in_tx(
    store: &Store,
    matcher: &dyn ContextMatcher,
    need: &ContextNeed,
) -> Result<usize, String> {
    let select = if matcher.exact_selector_role().is_some() {
        exact_offers_for_need_select(need)
    } else {
        matcher.wake_select_for_added_need(need)?
    };
    insert_pending_projection_from_select_in_tx(store, &select, "need")
}

fn wake_offer_in_tx(
    store: &Store,
    matcher: &dyn ContextMatcher,
    offer: &ContextOffer,
) -> Result<usize, String> {
    let select = if matcher.exact_selector_role().is_some() {
        exact_needs_for_offer_select(offer)
    } else {
        matcher.wake_select_for_added_offer(offer)?
    };
    insert_pending_projection_from_select_in_tx(store, &select, "offer")
}

fn insert_pending_projection_from_select_in_tx(
    store: &Store,
    select: &select::Select,
    edge_kind: &str,
) -> Result<usize, String> {
    select::insert_select_in_tx(store, PENDING_PROJECTION, &["owner"], select)
        .map_err(|err| format!("wake {edge_kind} from SELECT: {err}"))
}
