//! Build projection context from stored context edges.

use super::context_codec::scope_key;
use super::context_rows::{stored_offers_for_exact_match, stored_offers_for_role_scope};
use crate::core::context::{ContextNeed, ContextOffer, ContextSet, Role, Selector};
use crate::core::facts::FactScope;
use crate::core::matchers::ContextMatcher;
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

fn exact_context_key(role: &Role, scope: &FactScope, selector: &Selector) -> ExactContextKey {
    (role.clone(), scope.clone(), selector.clone())
}

fn exact_matcher_roles(matchers: &[&dyn ContextMatcher]) -> BTreeSet<Role> {
    matchers
        .iter()
        .filter_map(|matcher| matcher.exact_selector_role().cloned())
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
