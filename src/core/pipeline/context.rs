//! Standing context rows, projection context assembly, and context wake fanout.
//!
//! Context is core's dependency surface between facts. A projector can say
//! "this fact needs another fact with this role, scope, and selector before it
//! can finish" by emitting a `ContextNeed`, or "this fact provides payload for
//! matching needs" by emitting a `ContextOffer`. Core does not know the
//! protocol meaning of those relationships. It either matches the stable
//! role/scope/selector tuple exactly, or asks a protocol `ContextMatcher` to do
//! richer matching such as range, prefix, coverage, or visibility rules.
//!
//! This module is where that model becomes SQL. The public vocabulary lives in
//! `core::context`: needs, offers, roles, selectors, scopes, and complete
//! replacement `ContextSet`s. Protocol projectors in `core::projectors` produce
//! those sets. The projection loop in `pipeline::project_pending_facts` calls
//! this file to load a pending fact's previous standing context, assemble the
//! matched `ProjectionContext` it should see for the next run, replace its
//! stored needs and offers, and fan out wakeups to facts that may now make
//! progress. The matcher registry in `core::matchers` says which roles use
//! exact matching and which roles delegate to protocol-owned SQL.
//!
//! The stored shape is one `context_edges` row per standing need or offer. The
//! `owner` column is always the fact whose projection emitted the row. For
//! offers, that same owner is also the payload fact loaded into matched
//! projection context. Needs and offers are standing state, not event history:
//! when a fact projects again, its new output replaces the old rows it owned.
//!
//! The invariant is replacement by owner. Projection output is the complete
//! context set for one fact, and wake fanout considers only added rows from the
//! replacement delta. If matching semantics change, keep exact-equality SQL
//! here and put non-exact semantics behind a protocol `ContextMatcher`.

use crate::core::context::{
    scope_key, ContextNeed, ContextOffer, ContextSet, ContextSetDelta, Role, Selector,
};
use crate::core::fact_store::persisted_fact;
use crate::core::facts::{Fact, FactId, FactScope, ScopeKind};
use crate::core::matchers::{ContextMatcher, ContextMatchers};
use crate::core::projectors::{MatchedContext, ProjectionContext};
use crate::core::schema::{CONTEXT_EDGES, LOCAL_FACT_ADMISSIONS, PENDING_PROJECTION};
use crate::core::select;
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

/// Insert one standing offer row inside the projection transaction.
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

#[cfg(test)]
pub(crate) fn insert_context_need_for_test(
    store: &Store,
    need: &ContextNeed,
) -> Result<(), String> {
    store
        .write_transaction(|tx| insert_context_need_in_tx(tx, need).map(|_| ()))
        .map_err(|err| format!("insert context need: {err}"))
}

#[cfg(test)]
pub(crate) fn insert_context_offer_for_test(
    store: &Store,
    offer: &ContextOffer,
) -> Result<(), String> {
    store
        .write_transaction(|tx| insert_context_offer_in_tx(tx, offer).map(|_| ()))
        .map_err(|err| format!("insert context offer: {err}"))
}

/// Load exact context offers for a single match key.
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

/// Load all needs owned by one fact.
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

/// Load all offers owned by one fact.
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

/// Decode one persisted need row back into the public context type.
fn selected_context_need(row: &rusqlite::Row<'_>) -> rusqlite::Result<ContextNeed> {
    Ok(ContextNeed {
        owner: fact_id_column(row.get::<_, Vec<u8>>(0)?, "owner")?,
        role: Role::new(row.get::<_, String>(1)?).map_err(rusqlite::Error::InvalidParameterName)?,
        scope: decode_scope_key(&row.get::<_, Vec<u8>>(2)?)
            .map_err(rusqlite::Error::InvalidParameterName)?,
        selector: Selector::from_bytes(row.get::<_, Vec<u8>>(3)?),
    })
}

/// Decode one persisted offer row back into the public context type.
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

/// Decode the compact `scope_key` written by `context::scope_key`.
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

/// Find the offers that currently satisfy a set of needs.
///
/// Projection uses this both for a pending fact's previously stored needs and
/// for speculative needs emitted while preparing one projection. The input does
/// not have to be persisted yet. Matching still reads only already-stored offers,
/// and returned payloads are cached by offer owner so repeated matches do not
/// repeatedly load the same fact.
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
    let mut payloads = BTreeMap::new();
    for need in &context.needs {
        if exact_roles.contains(&need.role) {
            let key = exact_context_key(&need.role, &need.scope, &need.selector);
            for offer in exact_offers
                .get(&key)
                .into_iter()
                .flat_map(|offers| offers.iter())
            {
                push_stored_matched_context(
                    store,
                    need,
                    offer.clone(),
                    &mut seen,
                    &mut payloads,
                    &mut matched,
                )?;
            }
        }

        for matcher in matchers.custom_for_role(&need.role) {
            let candidate_offers = matcher.matching_offers_for_need_from_store(store, need)?;
            for offer in candidate_offers {
                push_stored_matched_context(
                    store,
                    need,
                    offer,
                    &mut seen,
                    &mut payloads,
                    &mut matched,
                )?;
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

/// Add a matched pair and load the offer owner's payload fact.
///
/// A missing payload is a storage invariant failure: context offers are only
/// useful because their owner fact is the payload exposed to projection.
fn push_stored_matched_context(
    store: &Store,
    need: &ContextNeed,
    offer: ContextOffer,
    seen: &mut BTreeSet<(ContextNeed, ContextOffer)>,
    payloads: &mut BTreeMap<FactId, Fact>,
    matched: &mut Vec<MatchedContext>,
) -> Result<(), String> {
    if !seen.insert((need.clone(), offer.clone())) {
        return Ok(());
    }
    let payload = if let Some(payload) = payloads.get(&offer.owner) {
        payload.clone()
    } else {
        let payload = persisted_fact(store, &offer.owner)?
            .ok_or_else(|| "context offer owner references unknown fact".to_string())?;
        payloads.insert(offer.owner, payload.clone());
        payload
    };
    matched.push(MatchedContext {
        need: need.clone(),
        offer,
        payload,
    });
    Ok(())
}

/// Insert pending owners woken by newly added context rows.
///
/// Removals do not wake projection. A projector that stops needing context has
/// already run; dependent facts wake only when a new need can now be satisfied
/// or a new offer may satisfy existing needs.
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
