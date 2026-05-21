//! SQL helpers for waking facts after context edge additions.

use super::context_rows::{stored_needs_for_role_scope, stored_offers_for_role_scope};
use crate::core::context::{scope_key, ContextSetDelta};
use crate::core::context::{ContextNeed, ContextOffer};
use crate::core::matchers::{ContextMatch, ContextMatcher};
use crate::core::schema::{CONTEXT_EDGES, FACTS, PENDING_PROJECTION};
use crate::core::store::{ColumnValue, Store};
use crate::core::wake;
use std::collections::HashSet;

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

fn exact_offers_for_need_select(need: &ContextNeed) -> wake::Select {
    let scope_key = scope_key(&need.scope);
    wake::Select::new(
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
            wake::Param::bytes(":need_owner", need.owner),
            wake::Param::text(":role", need.role.as_str()),
            wake::Param::bytes(":scope_key", scope_key),
            wake::Param::bytes(":selector", need.selector.as_bytes()),
        ],
    )
}

fn exact_needs_for_offer_select(offer: &ContextOffer) -> wake::Select {
    let scope_key = scope_key(&offer.scope);
    wake::Select::new(
        r#"
        SELECT n.owner
        FROM context_edges n
        JOIN facts f ON f.id = n.owner
        WHERE n.direction = 'need'
          AND n.role = :role
          AND n.scope_key = :scope_key
          AND n.selector = :selector
        ORDER BY f.timestamp, n.owner
        "#,
        &[CONTEXT_EDGES, FACTS],
        vec![
            wake::Param::text(":role", offer.role.as_str()),
            wake::Param::bytes(":scope_key", scope_key),
            wake::Param::bytes(":selector", offer.selector.as_bytes()),
        ],
    )
}

fn wake_need_in_tx(
    store: &Store,
    matcher: &dyn ContextMatcher,
    need: &ContextNeed,
) -> Result<usize, String> {
    let select = if matcher.exact_selector_role().is_some() {
        Some(exact_offers_for_need_select(need))
    } else {
        matcher.wake_select_for_added_need(need)?
    };
    if let Some(select) = select {
        return insert_pending_projection_from_select_in_tx(store, &select, "need");
    }

    let offers = if let Some(offers) = matcher.matching_offers_for_need_from_store(store, need)? {
        offers
    } else {
        stored_offers_for_role_scope(store, &need.role, &need.scope)?
    };
    let matches = matcher.match_new_need(need, &offers);
    wake_matched_need_owners_in_tx(store, matches)
        .map_err(|err| format!("wake need from Rust matcher: {err}"))
}

fn wake_offer_in_tx(
    store: &Store,
    matcher: &dyn ContextMatcher,
    offer: &ContextOffer,
) -> Result<usize, String> {
    let select = if matcher.exact_selector_role().is_some() {
        Some(exact_needs_for_offer_select(offer))
    } else {
        matcher.wake_select_for_added_offer(offer)?
    };
    if let Some(select) = select {
        return insert_pending_projection_from_select_in_tx(store, &select, "offer");
    }

    let needs = if let Some(needs) = matcher.matching_needs_for_offer_from_store(store, offer)? {
        needs
    } else {
        stored_needs_for_role_scope(store, &offer.role, &offer.scope)?
    };
    let matches = matcher.match_new_offer(offer, &needs);
    wake_matched_need_owners_in_tx(store, matches)
        .map_err(|err| format!("wake offer from Rust matcher: {err}"))
}

fn insert_pending_projection_from_select_in_tx(
    store: &Store,
    select: &wake::Select,
    edge_kind: &str,
) -> Result<usize, String> {
    wake::insert_select_in_tx(store, PENDING_PROJECTION, &["owner"], select)
        .map_err(|err| format!("wake {edge_kind} from SELECT: {err}"))
}

fn wake_matched_need_owners_in_tx(
    store: &Store,
    matches: Vec<ContextMatch>,
) -> rusqlite::Result<usize> {
    let mut inserted = 0usize;
    let mut seen = HashSet::new();
    for matched in matches {
        if seen.insert(matched.need_owner)
            && store.insert_typed_row_in_tx(
                PENDING_PROJECTION,
                &[("owner", ColumnValue::Bytes(&matched.need_owner))],
            )?
        {
            inserted += 1;
        }
    }
    Ok(inserted)
}
