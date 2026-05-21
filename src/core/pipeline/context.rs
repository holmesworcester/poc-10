//! Standing context rows, projection context assembly, and context wake fanout.

use crate::core::context::{
    scope_key, ContextNeed, ContextOffer, ContextSet, ContextSetDelta, Role, Selector,
};
use crate::core::fact_store::persisted_fact;
use crate::core::facts::{FactId, FactScope, ScopeKind};
use crate::core::matchers::ContextMatchers;
use crate::core::projectors::{MatchedContext, ProjectionContext};
use crate::core::store::Store;
use crate::core::wire::{Reader, WireError};
use rusqlite::params;
use std::collections::{BTreeMap, BTreeSet};

const CONTEXT_NEED_DIRECTION: &str = "need";
const CONTEXT_OFFER_DIRECTION: &str = "offer";

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

pub(super) fn insert_context_need_in_tx(
    store: &Store,
    need: &ContextNeed,
) -> rusqlite::Result<bool> {
    insert_context_edge_in_tx(
        store,
        &need.owner,
        CONTEXT_NEED_DIRECTION,
        &need.role,
        &need.scope,
        need.selector.as_bytes(),
    )
}

pub(super) fn insert_context_offer_in_tx(
    store: &Store,
    offer: &ContextOffer,
) -> rusqlite::Result<bool> {
    insert_context_edge_in_tx(
        store,
        &offer.owner,
        CONTEXT_OFFER_DIRECTION,
        &offer.role,
        &offer.scope,
        offer.selector.as_bytes(),
    )
}

pub(super) fn stored_offers_for_exact_match(
    store: &Store,
    role: &Role,
    scope_key: &[u8],
    selector: &[u8],
) -> Result<Vec<ContextOffer>, String> {
    select_context_offers(
        store,
        r#"
        SELECT owner, role, scope_key, selector
        FROM context_edges
        WHERE direction = 'offer'
          AND role = :role
          AND scope_key = :scope_key
          AND selector = :selector
        ORDER BY owner
        "#,
        &[
            (":role", text(role.as_str())),
            (":scope_key", bytes(scope_key)),
            (":selector", bytes(selector)),
        ],
    )
}

fn stored_needs_for_owner(store: &Store, owner: &FactId) -> Result<Vec<ContextNeed>, String> {
    select_context_needs(
        store,
        r#"
        SELECT owner, role, scope_key, selector
        FROM context_edges
        WHERE owner = :owner
          AND direction = 'need'
        ORDER BY owner, role, scope_key, selector
        "#,
        &[(":owner", bytes(owner))],
    )
}

fn stored_offers_for_owner(store: &Store, owner: &FactId) -> Result<Vec<ContextOffer>, String> {
    select_context_offers(
        store,
        r#"
        SELECT owner, role, scope_key, selector
        FROM context_edges
        WHERE owner = :owner
          AND direction = 'offer'
        ORDER BY owner, role, scope_key, selector
        "#,
        &[(":owner", bytes(owner))],
    )
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
        FROM context_edges
        WHERE direction = 'need'
          AND role = :role
          AND scope_key = :scope_key
        ORDER BY owner, selector
        "#,
        &[
            (":role", text(role.as_str())),
            (":scope_key", bytes(&scope_key)),
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
        FROM context_edges
        WHERE direction = 'offer'
          AND role = :role
          AND scope_key = :scope_key
        ORDER BY owner, selector
        "#,
        &[
            (":role", text(role.as_str())),
            (":scope_key", bytes(&scope_key)),
        ],
    )
}

fn select_context_needs(
    store: &Store,
    sql: &str,
    params: &[(&str, rusqlite::types::Value)],
) -> Result<Vec<ContextNeed>, String> {
    let mut stmt = store
        .conn()
        .prepare(sql)
        .map_err(|err| format!("load context needs: {err}"))?;
    bind_named_params(&mut stmt, params).map_err(|err| format!("load context needs: {err}"))?;
    let rows = stmt
        .raw_query()
        .mapped(selected_context_need)
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("load context needs: {err}"))?;
    Ok(rows)
}

fn select_context_offers(
    store: &Store,
    sql: &str,
    params: &[(&str, rusqlite::types::Value)],
) -> Result<Vec<ContextOffer>, String> {
    let mut stmt = store
        .conn()
        .prepare(sql)
        .map_err(|err| format!("load context offers: {err}"))?;
    bind_named_params(&mut stmt, params).map_err(|err| format!("load context offers: {err}"))?;
    let rows = stmt
        .raw_query()
        .mapped(selected_context_offer)
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("load context offers: {err}"))?;
    Ok(rows)
}

fn insert_context_edge_in_tx(
    store: &Store,
    owner: &FactId,
    direction: &str,
    role: &Role,
    scope: &FactScope,
    selector: &[u8],
) -> rusqlite::Result<bool> {
    let scope_key = scope_key(scope);
    store
        .conn()
        .execute(
            "INSERT OR IGNORE INTO context_edges
                (owner, direction, role, scope_key, selector)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                owner.as_slice(),
                direction,
                role.as_str(),
                scope_key.as_slice(),
                selector
            ],
        )
        .map(|count| count > 0)
}

fn selected_context_need(row: &rusqlite::Row<'_>) -> rusqlite::Result<ContextNeed> {
    Ok(ContextNeed {
        owner: fact_id_column(row.get::<_, Vec<u8>>(0)?, "owner")?,
        role: Role::new(row.get::<_, String>(1)?).map_err(rusqlite::Error::InvalidParameterName)?,
        scope: decode_scope_key(&row.get::<_, Vec<u8>>(2)?)
            .map_err(rusqlite::Error::InvalidParameterName)?,
        selector: Selector::from_bytes(row.get::<_, Vec<u8>>(3)?),
    })
}

fn selected_context_offer(row: &rusqlite::Row<'_>) -> rusqlite::Result<ContextOffer> {
    Ok(ContextOffer {
        owner: fact_id_column(row.get::<_, Vec<u8>>(0)?, "owner")?,
        role: Role::new(row.get::<_, String>(1)?).map_err(rusqlite::Error::InvalidParameterName)?,
        scope: decode_scope_key(&row.get::<_, Vec<u8>>(2)?)
            .map_err(rusqlite::Error::InvalidParameterName)?,
        selector: Selector::from_bytes(row.get::<_, Vec<u8>>(3)?),
    })
}

fn bind_named_params(
    stmt: &mut rusqlite::Statement<'_>,
    params: &[(&str, rusqlite::types::Value)],
) -> rusqlite::Result<()> {
    for (name, value) in params {
        let index = stmt.parameter_index(name)?.ok_or_else(|| {
            rusqlite::Error::InvalidParameterName(format!(
                "context SQL does not bind parameter {name}"
            ))
        })?;
        stmt.raw_bind_parameter(index, value)?;
    }
    Ok(())
}

fn fact_id_column(bytes: Vec<u8>, name: &str) -> rusqlite::Result<FactId> {
    bytes.try_into().map_err(|_| {
        rusqlite::Error::InvalidParameterName(format!("context SQL column {name} is not a fact id"))
    })
}

fn bytes(value: &[u8]) -> rusqlite::types::Value {
    rusqlite::types::Value::Blob(value.to_vec())
}

fn text(value: &str) -> rusqlite::types::Value {
    rusqlite::types::Value::Text(value.to_string())
}

fn decode_scope_key(bytes: &[u8]) -> Result<FactScope, String> {
    let mut reader = Reader::new(bytes);
    let scope = decode_scope(&mut reader)?;
    reader.finish().row()?;
    Ok(scope)
}

fn decode_scope(reader: &mut Reader<'_>) -> Result<FactScope, String> {
    match reader.u8().row()? {
        0 => Ok(FactScope::Global),
        1 => Ok(FactScope::Local),
        2 => {
            let kind = ScopeKind::new(reader.string_u16be().row()?)?;
            let id = reader.array::<32>().row()?;
            Ok(FactScope::Scoped { kind, id })
        }
        other => Err(format!("invalid fact scope tag {other}")),
    }
}

trait RowWireResult<T> {
    fn row(self) -> Result<T, String>;
}

impl<T> RowWireResult<T> for Result<T, WireError> {
    fn row(self) -> Result<T, String> {
        self.map_err(|err| format!("invalid encoded row: {err}"))
    }
}

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
            let candidate_offers = stored_offers_for_role_scope(store, &need.role, &need.scope)?;
            for offer in candidate_offers
                .into_iter()
                .filter(|offer| matcher.matches(need, offer))
            {
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
        inserted += wake_exact_need_in_tx(store, need)?;
    }
    for offer in delta
        .added_offers
        .iter()
        .filter(|offer| matchers.has_exact_role(&offer.role))
    {
        inserted += wake_exact_offer_in_tx(store, offer)?;
    }
    for matcher in matchers.custom() {
        for need in delta
            .added_needs
            .iter()
            .filter(|need| matcher.role() == &need.role)
        {
            let has_match = stored_offers_for_role_scope(store, &need.role, &need.scope)?
                .iter()
                .any(|offer| matcher.matches(need, offer));
            if has_match {
                inserted += insert_pending_owners_in_tx(store, &[need.owner])?;
            }
        }
        for offer in delta
            .added_offers
            .iter()
            .filter(|offer| matcher.role() == &offer.role)
        {
            let owners = stored_needs_for_role_scope(store, &offer.role, &offer.scope)?
                .into_iter()
                .filter(|need| matcher.matches(need, offer))
                .map(|need| need.owner)
                .collect::<Vec<_>>();
            inserted += insert_pending_owners_in_tx(store, &owners)?;
        }
    }
    Ok(inserted)
}

fn wake_exact_need_in_tx(store: &Store, need: &ContextNeed) -> Result<usize, String> {
    let scope_key = scope_key(&need.scope);
    store
        .conn()
        .execute(
            r#"
            INSERT OR IGNORE INTO pending_projection (owner)
            SELECT ?1
            WHERE EXISTS (
            SELECT 1
            FROM context_edges
            WHERE direction = 'offer'
              AND role = ?2
              AND scope_key = ?3
              AND selector = ?4
        )
        "#,
            params![
                need.owner.as_slice(),
                need.role.as_str(),
                scope_key.as_slice(),
                need.selector.as_bytes(),
            ],
        )
        .map_err(|err| format!("wake exact need: {err}"))
}

fn wake_exact_offer_in_tx(store: &Store, offer: &ContextOffer) -> Result<usize, String> {
    let scope_key = scope_key(&offer.scope);
    store
        .conn()
        .execute(
            r#"
            INSERT OR IGNORE INTO pending_projection (owner)
            SELECT n.owner
            FROM context_edges n
            JOIN local_fact_admissions a ON a.fact_id = n.owner
            WHERE n.direction = 'need'
              AND n.role = ?1
              AND n.scope_key = ?2
              AND n.selector = ?3
            ORDER BY a.received_at, n.owner
            "#,
            params![
                offer.role.as_str(),
                scope_key.as_slice(),
                offer.selector.as_bytes(),
            ],
        )
        .map_err(|err| format!("wake exact offer: {err}"))
}

fn insert_pending_owners_in_tx(store: &Store, owners: &[FactId]) -> Result<usize, String> {
    let mut stmt = store
        .conn()
        .prepare("INSERT OR IGNORE INTO pending_projection (owner) VALUES (?1)")
        .map_err(|err| format!("wake custom context: {err}"))?;
    let mut inserted = 0usize;
    for owner in owners {
        inserted += stmt
            .execute(params![owner.as_slice()])
            .map_err(|err| format!("wake custom context: {err}"))?;
    }
    Ok(inserted)
}
