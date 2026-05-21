//! Build projection context from stored context edges.

use super::context_rows::stored_offers_for_exact_match;
use crate::core::context::{
    scope_key, ContextNeed, ContextOffer, ContextSet, ContextSetDelta, Role, Selector,
};
use crate::core::fact_store::persisted_fact;
use crate::core::facts::FactScope;
use crate::core::matchers::{ContextMatcher, ContextMatchers};
use crate::core::projectors::{MatchedContext, ProjectionContext};
use crate::core::schema::{CONTEXT_EDGES, LOCAL_FACT_ADMISSIONS, PENDING_PROJECTION};
use crate::core::select;
use crate::core::store::Store;
use std::collections::{BTreeMap, BTreeSet};

type ExactContextKey = (Role, FactScope, Selector);

/// Find the offers that currently satisfy a fact's needs.
pub(super) fn stored_matching_context(
    store: &Store,
    context: &ContextSet,
    matchers: &ContextMatchers,
) -> Result<ProjectionContext, String> {
    if context.needs.is_empty() {
        return Ok(ProjectionContext::new(Vec::new()));
    }

    let exact_roles = matchers.exact_roles();
    let exact_offers = stored_exact_offers_for_needs(
        store,
        context
            .needs
            .iter()
            .filter(|need| exact_roles.contains(&need.role)),
    )?;
    let mut matched = Vec::new();
    let mut seen = BTreeSet::new();
    for need in &context.needs {
        if exact_roles.contains(&need.role) {
            let key = exact_context_key(&need.role, &need.scope, &need.selector);
            for offer in exact_offers
                .get(&key)
                .into_iter()
                .flat_map(|offers| offers.iter())
            {
                push_stored_matched_context(store, need, offer.clone(), &mut seen, &mut matched)?;
            }
        }

        for matcher in matchers.custom_for_role(&need.role) {
            let candidate_offers = matcher.matching_offers_for_need_from_store(store, need)?;
            for offer in candidate_offers {
                push_stored_matched_context(store, need, offer, &mut seen, &mut matched)?;
            }
        }
    }
    Ok(ProjectionContext::from_matches(matched))
}

fn exact_context_key(role: &Role, scope: &FactScope, selector: &Selector) -> ExactContextKey {
    (role.clone(), scope.clone(), selector.clone())
}

fn stored_exact_offers_for_needs<'a>(
    store: &Store,
    needs: impl Iterator<Item = &'a ContextNeed>,
) -> Result<BTreeMap<ExactContextKey, Vec<ContextOffer>>, String> {
    let mut groups = BTreeMap::<(Role, Vec<u8>), BTreeSet<Vec<u8>>>::new();
    for need in needs {
        groups
            .entry((need.role.clone(), scope_key(&need.scope)))
            .or_default()
            .insert(need.selector.as_bytes().to_vec());
    }

    let mut out = BTreeMap::<ExactContextKey, Vec<ContextOffer>>::new();
    for ((role, scope_key), selectors) in groups {
        for selector in selectors {
            let offers = stored_offers_for_exact_match(store, &role, &scope_key, &selector)?;
            for offer in offers {
                out.entry(exact_context_key(
                    &offer.role,
                    &offer.scope,
                    &offer.selector,
                ))
                .or_default()
                .push(offer);
            }
        }
    }
    Ok(out)
}

fn push_stored_matched_context(
    store: &Store,
    need: &ContextNeed,
    offer: ContextOffer,
    seen: &mut BTreeSet<(ContextNeed, ContextOffer)>,
    matched: &mut Vec<MatchedContext>,
) -> Result<(), String> {
    if !seen.insert((need.clone(), offer.clone())) {
        return Ok(());
    }
    let payload = persisted_fact(store, &offer.owner)?
        .ok_or_else(|| "context offer owner references unknown fact".to_string())?;
    matched.push(MatchedContext {
        need: need.clone(),
        offer,
        payload,
    });
    Ok(())
}

pub(super) fn wake_context_matches_in_tx(
    store: &Store,
    delta: &ContextSetDelta,
    matchers: &ContextMatchers,
) -> Result<usize, String> {
    let mut inserted = 0usize;
    for need in delta
        .added_needs
        .iter()
        .filter(|need| matchers.has_exact_role(&need.role))
    {
        inserted += insert_pending_projection_from_select_in_tx(
            store,
            &exact_offers_for_need_select(need),
            "need",
        )?;
    }
    for offer in delta
        .added_offers
        .iter()
        .filter(|offer| matchers.has_exact_role(&offer.role))
    {
        inserted += insert_pending_projection_from_select_in_tx(
            store,
            &exact_needs_for_offer_select(offer),
            "offer",
        )?;
    }
    for matcher in matchers.custom() {
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
    let select = matcher.wake_select_for_added_need(need)?;
    insert_pending_projection_from_select_in_tx(store, &select, "need")
}

fn wake_offer_in_tx(
    store: &Store,
    matcher: &dyn ContextMatcher,
    offer: &ContextOffer,
) -> Result<usize, String> {
    let select = matcher.wake_select_for_added_offer(offer)?;
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
