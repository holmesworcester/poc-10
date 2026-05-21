//! Build projection context and custom context wake matches from SQL rows.

use super::context_codec::scope_key;
use super::context_rows::{
    stored_needs_for_role_scope, stored_offers_for_exact_match, stored_offers_for_role_scope,
};
use crate::core::context::{
    ContextNeed, ContextOffer, ContextSet, ContextSetDelta, Role, Selector,
};
use crate::core::facts::FactScope;
use crate::core::matchers::{ContextMatch, ContextMatcher};
use crate::core::pipeline_storage::persisted_fact;
use crate::core::projectors::{MatchedContext, ProjectionContext};
use crate::core::store::Store;
use std::collections::{BTreeMap, BTreeSet};

type ExactContextKey = (Role, FactScope, Selector);

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
