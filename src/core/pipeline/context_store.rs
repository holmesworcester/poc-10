//! SQL-backed context storage and matching helpers.
//!
//! Context rows are declared typed SQLite tables. This module keeps the
//! higher-level reads and matcher queries over those tables.

use super::context_codec::{
    scope_key, selected_fact_id, selected_role, selected_scope, selected_selector,
    CONTEXT_ROW_COLUMNS,
};
use crate::core::context::{
    ContextNeed, ContextOffer, ContextSet, ContextSetDelta, Role, Selector,
};
use crate::core::facts::{FactId, FactScope};
use crate::core::matchers::{ContextMatch, ContextMatcher};
use crate::core::pipeline::{CONTEXT_NEEDS, CONTEXT_OFFERS};
use crate::core::pipeline_storage::persisted_fact;
use crate::core::projectors::{MatchedContext, ProjectionContext};
use crate::core::store::{ColumnValue, SelectedRow, Store};
use std::collections::{BTreeMap, BTreeSet};

type ExactContextKey = (Role, FactScope, Selector);

/// Load a fact's standing context, returning `None` when it has none.
pub(crate) fn persisted_context(
    store: &Store,
    owner: &FactId,
) -> Result<Option<ContextSet>, String> {
    let context = stored_context_for_owner(store, owner)?;
    if context.needs.is_empty() && context.offers.is_empty() {
        Ok(None)
    } else {
        Ok(Some(context))
    }
}

/// Load a fact's standing context: the needs and offers it currently owns.
pub(super) fn stored_context_for_owner(
    store: &Store,
    owner: &FactId,
) -> Result<ContextSet, String> {
    Ok(ContextSet {
        needs: stored_needs_for_owner(store, owner)?,
        offers: stored_offers_for_owner(store, owner)?,
    }
    .normalized())
}

/// Find the offers that currently satisfy a fact's needs.
pub(super) fn stored_matching_context(
    store: &Store,
    context: &ContextSet,
    matchers: &[&dyn ContextMatcher],
) -> Result<ProjectionContext, String> {
    if context.needs.is_empty() {
        return Ok(ProjectionContext::new(Vec::new()));
    }

    let exact_roles = exact_matcher_roles(matchers);
    let exact_offers = stored_exact_offers_for_needs(
        store,
        context
            .needs
            .iter()
            .filter(|need| exact_roles.contains(&need.role)),
    )?;
    let custom_matchers = matchers
        .iter()
        .copied()
        .filter(|matcher| {
            matcher.exact_selector_role().is_none()
                && context
                    .needs
                    .iter()
                    .any(|need| &need.role == matcher.role())
        })
        .collect::<Vec<_>>();

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

        for matcher in custom_matchers
            .iter()
            .copied()
            .filter(|matcher| matcher.role() == &need.role)
        {
            let candidate_offers =
                if let Some(offers) = matcher.matching_offers_for_need_from_store(store, need)? {
                    offers
                } else {
                    stored_offers_for_role_scope(store, &need.role, &need.scope)?
                };
            for offer in candidate_offers {
                push_stored_matched_context(store, need, offer, &mut seen, &mut matched)?;
            }
        }
    }
    Ok(ProjectionContext::from_matches(matched))
}

/// Find the need/offer pairs newly satisfiable because of `delta`.
pub(super) fn stored_context_matches(
    store: &Store,
    delta: &ContextSetDelta,
    matchers: &[&dyn ContextMatcher],
) -> Result<Vec<ContextMatch>, String> {
    let mut matches = BTreeSet::new();
    let custom_matchers = relevant_custom_matchers_for_delta(matchers, delta);
    for matcher in custom_matchers {
        for need in delta
            .added_needs
            .iter()
            .filter(|need| matcher.role() == &need.role)
        {
            if let Some(offers) = matcher.matching_offers_for_need_from_store(store, need)? {
                matches.extend(offers.into_iter().map(|offer| ContextMatch {
                    need_owner: need.owner,
                    offer_owner: offer.owner,
                }));
            } else {
                let offers = stored_offers_for_role_scope(store, &need.role, &need.scope)?;
                matches.extend(matcher.match_new_need(need, &offers));
            }
        }
        for offer in delta
            .added_offers
            .iter()
            .filter(|offer| matcher.role() == &offer.role)
        {
            if let Some(needs) = matcher.matching_needs_for_offer_from_store(store, offer)? {
                matches.extend(needs.into_iter().map(|need| ContextMatch {
                    need_owner: need.owner,
                    offer_owner: offer.owner,
                }));
            } else {
                let needs = stored_needs_for_role_scope(store, &offer.role, &offer.scope)?;
                matches.extend(matcher.match_new_offer(offer, &needs));
            }
        }
    }

    let mut out = matches.into_iter().collect::<Vec<_>>();
    out.sort_by_key(|matched| {
        (
            persisted_fact(store, &matched.need_owner)
                .ok()
                .flatten()
                .map(|fact| fact.timestamp)
                .unwrap_or(u64::MAX),
            matched.need_owner,
        )
    });
    Ok(out)
}

pub(super) fn insert_context_offer_in_tx(
    store: &Store,
    offer: &ContextOffer,
) -> rusqlite::Result<bool> {
    store.insert_typed_row_in_tx(
        CONTEXT_OFFERS,
        &[
            ("owner", ColumnValue::Bytes(&offer.owner)),
            ("role", ColumnValue::Text(offer.role.as_str())),
            ("scope_key", ColumnValue::Bytes(&scope_key(&offer.scope))),
            ("selector", ColumnValue::Bytes(offer.selector.as_bytes())),
        ],
    )
}

fn exact_context_key(role: &Role, scope: &FactScope, selector: &Selector) -> ExactContextKey {
    (role.clone(), scope.clone(), selector.clone())
}

fn exact_matcher_roles(matchers: &[&dyn ContextMatcher]) -> BTreeSet<Role> {
    matchers
        .iter()
        .filter_map(|matcher| matcher.exact_selector_role().cloned())
        .collect()
}

fn relevant_custom_matchers_for_delta<'a>(
    matchers: &[&'a dyn ContextMatcher],
    delta: &ContextSetDelta,
) -> Vec<&'a dyn ContextMatcher> {
    matchers
        .iter()
        .copied()
        .filter(|matcher| {
            matcher.exact_selector_role().is_none()
                && (delta
                    .added_needs
                    .iter()
                    .any(|need| &need.role == matcher.role())
                    || delta
                        .added_offers
                        .iter()
                        .any(|offer| &offer.role == matcher.role()))
        })
        .collect()
}

fn stored_needs_for_owner(store: &Store, owner: &FactId) -> Result<Vec<ContextNeed>, String> {
    select_context_needs(
        store,
        r#"
        SELECT owner, role, scope_key, selector
        FROM context_needs
        WHERE owner = :owner
        ORDER BY owner, role, scope_key, selector
        "#,
        &[(":owner", ColumnValue::Bytes(owner))],
    )
}

fn stored_offers_for_owner(store: &Store, owner: &FactId) -> Result<Vec<ContextOffer>, String> {
    select_context_offers(
        store,
        r#"
        SELECT owner, role, scope_key, selector
        FROM context_offers
        WHERE owner = :owner
        ORDER BY owner, role, scope_key, selector
        "#,
        &[(":owner", ColumnValue::Bytes(owner))],
    )
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
            let offers = select_context_offers(
                store,
                r#"
                SELECT owner, role, scope_key, selector
                FROM context_offers
                WHERE role = :role
                  AND scope_key = :scope_key
                  AND selector = :selector
                ORDER BY owner
                "#,
                &[
                    (":role", ColumnValue::Text(role.as_str())),
                    (":scope_key", ColumnValue::Bytes(&scope_key)),
                    (":selector", ColumnValue::Bytes(&selector)),
                ],
            )?;
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

fn stored_needs_for_role_scope(
    store: &Store,
    role: &Role,
    scope: &FactScope,
) -> Result<Vec<ContextNeed>, String> {
    let scope_key = scope_key(scope);
    select_context_needs(
        store,
        r#"
        SELECT owner, role, scope_key, selector
        FROM context_needs
        WHERE role = :role
          AND scope_key = :scope_key
        ORDER BY owner, selector
        "#,
        &[
            (":role", ColumnValue::Text(role.as_str())),
            (":scope_key", ColumnValue::Bytes(&scope_key)),
        ],
    )
}

fn stored_offers_for_role_scope(
    store: &Store,
    role: &Role,
    scope: &FactScope,
) -> Result<Vec<ContextOffer>, String> {
    let scope_key = scope_key(scope);
    select_context_offers(
        store,
        r#"
        SELECT owner, role, scope_key, selector
        FROM context_offers
        WHERE role = :role
          AND scope_key = :scope_key
        ORDER BY owner, selector
        "#,
        &[
            (":role", ColumnValue::Text(role.as_str())),
            (":scope_key", ColumnValue::Bytes(&scope_key)),
        ],
    )
}

fn select_context_needs(
    store: &Store,
    sql: &str,
    params: &[(&str, ColumnValue<'_>)],
) -> Result<Vec<ContextNeed>, String> {
    store
        .select_only(sql, &[CONTEXT_NEEDS], params, CONTEXT_ROW_COLUMNS)
        .map_err(|err| format!("load context needs: {err}"))?
        .into_iter()
        .map(selected_context_need)
        .collect()
}

fn select_context_offers(
    store: &Store,
    sql: &str,
    params: &[(&str, ColumnValue<'_>)],
) -> Result<Vec<ContextOffer>, String> {
    store
        .select_only(sql, &[CONTEXT_OFFERS], params, CONTEXT_ROW_COLUMNS)
        .map_err(|err| format!("load context offers: {err}"))?
        .into_iter()
        .map(selected_context_offer)
        .collect()
}

fn selected_context_need(row: SelectedRow) -> Result<ContextNeed, String> {
    Ok(ContextNeed {
        owner: selected_fact_id(&row, "owner")?,
        role: selected_role(&row)?,
        scope: selected_scope(&row)?,
        selector: selected_selector(&row)?,
    })
}

fn selected_context_offer(row: SelectedRow) -> Result<ContextOffer, String> {
    Ok(ContextOffer {
        owner: selected_fact_id(&row, "owner")?,
        role: selected_role(&row)?,
        scope: selected_scope(&row)?,
        selector: selected_selector(&row)?,
    })
}
