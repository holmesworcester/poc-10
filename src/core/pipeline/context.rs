//! Standing context rows, projection context assembly, and context wake fanout.
//!
//! Context is core's dependency surface between facts. A projector can say
//! "this fact needs another fact with this role, scope, and byte range before it
//! can finish" by emitting a `ContextNeed`, or "this fact provides payload for
//! matching needs" by emitting a `ContextOffer`. Core does not know the
//! protocol meaning of those relationships. It matches only stable role/scope
//! partitions plus inclusive byte-range overlap.
//!
//! This module is where that model becomes SQL. The public vocabulary lives in
//! `core::context`: needs, offers, roles, keys, scopes, and complete
//! replacement `ContextSet`s. Protocol projectors in `core::projectors` produce
//! those sets. The projection loop in `pipeline::project_pending_facts` calls
//! this file to load a pending fact's previous standing context, assemble the
//! matched `ProjectionContext` it should see for the next run, replace its
//! stored needs and offers, and fan out wakeups to facts that may now make
//! progress.
//!
//! The stored shape is one `context_edges` row per standing need or offer. The
//! `owner` column is always the fact whose projection emitted the row. For
//! offers, that same owner is also the payload fact loaded into matched
//! projection context. Needs and offers are standing state, not fact history:
//! when a fact projects again, its new output replaces the old rows it owned.
//!
//! The invariant is replacement by owner. Projection output is the complete
//! context set for one fact, and wake fanout considers only added rows from the
//! replacement delta. If protocol semantics change, keep the generic overlap
//! query here and change the domain-owned key encoders/validators.

use crate::core::context::{
    scope_key, ContextKey, ContextNeed, ContextOffer, ContextSet, ContextSetDelta, Role,
};
use crate::core::fact_store::{mark_projection_pending_in_tx, persisted_fact};
use crate::core::facts::{Fact, FactId, FactScope, ScopeKind};
use crate::core::projectors::{MatchedContext, ProjectionContext};
use crate::core::schema::{CONTEXT_EDGES, LOCAL_FACT_ADMISSIONS};
use crate::core::store::Store;
use crate::core::wire::{Reader, WireError};
use rusqlite::params;
use std::collections::{BTreeMap, BTreeSet};

use super::insert_select;

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
        need.start_key.as_bytes(),
        need.end_key.as_bytes(),
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
        offer.start_key.as_bytes(),
        offer.end_key.as_bytes(),
    )
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

/// Load context offers whose range overlaps a single need range.
pub(super) fn stored_overlapping_offers_for_need(
    store: &Store,
    need: &ContextNeed,
) -> Result<Vec<ContextOffer>, String> {
    let scope_key = scope_key(&need.scope);
    select_context_offers(
        store,
        r#"
        SELECT owner, role, scope_key, start_key, end_key
        FROM context_edges
        WHERE direction = 'offer'
          AND role = :role
          AND scope_key = :scope_key
          AND start_key <= :need_end
          AND end_key >= :need_start
        ORDER BY owner, start_key, end_key
        "#,
        &[
            (":role", text(need.role.as_str())),
            (":scope_key", bytes(&scope_key)),
            (":need_start", bytes(need.start_key.as_bytes())),
            (":need_end", bytes(need.end_key.as_bytes())),
        ],
    )
}

/// Load all needs owned by one fact.
fn stored_needs_for_owner(store: &Store, owner: &FactId) -> Result<Vec<ContextNeed>, String> {
    select_context_needs(
        store,
        r#"
        SELECT owner, role, scope_key, start_key, end_key
        FROM context_edges
        WHERE owner = :owner
          AND direction = 'need'
        ORDER BY owner, role, scope_key, start_key, end_key
        "#,
        &[(":owner", bytes(owner))],
    )
}

/// Load all offers owned by one fact.
fn stored_offers_for_owner(store: &Store, owner: &FactId) -> Result<Vec<ContextOffer>, String> {
    select_context_offers(
        store,
        r#"
        SELECT owner, role, scope_key, start_key, end_key
        FROM context_edges
        WHERE owner = :owner
          AND direction = 'offer'
        ORDER BY owner, role, scope_key, start_key, end_key
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
    start_key: &[u8],
    end_key: &[u8],
) -> rusqlite::Result<bool> {
    let scope_key = scope_key(scope);
    store
        .conn()
        .execute(
            "INSERT OR IGNORE INTO context_edges
                (owner, direction, role, scope_key, start_key, end_key)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                owner.as_slice(),
                direction,
                role.as_str(),
                scope_key.as_slice(),
                start_key,
                end_key
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
        start_key: ContextKey::from_bytes(row.get::<_, Vec<u8>>(3)?),
        end_key: ContextKey::from_bytes(row.get::<_, Vec<u8>>(4)?),
    })
}

/// Decode one persisted offer row back into the public context type.
fn selected_context_offer(row: &rusqlite::Row<'_>) -> rusqlite::Result<ContextOffer> {
    Ok(ContextOffer {
        owner: fact_id_column(row.get::<_, Vec<u8>>(0)?, "owner")?,
        role: Role::new(row.get::<_, String>(1)?).map_err(rusqlite::Error::InvalidParameterName)?,
        scope: decode_scope_key(&row.get::<_, Vec<u8>>(2)?)
            .map_err(rusqlite::Error::InvalidParameterName)?,
        start_key: ContextKey::from_bytes(row.get::<_, Vec<u8>>(3)?),
        end_key: ContextKey::from_bytes(row.get::<_, Vec<u8>>(4)?),
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

/// Find the offers that currently satisfy a set of needs.
///
/// Projection uses this both for a pending fact's previously stored needs and
/// for speculative needs emitted while preparing one projection. The input does
/// not have to be persisted yet. Matching still reads only already-stored
/// offers, and returned payloads are cached by offer owner so repeated matches
/// do not repeatedly load the same fact.
pub(super) fn stored_matching_context(
    store: &Store,
    context: &ContextSet,
) -> Result<ProjectionContext, String> {
    if context.needs.is_empty() {
        return Ok(ProjectionContext::new(Vec::new()));
    }

    let mut matched = Vec::new();
    let mut seen = BTreeSet::new();
    let mut payloads = BTreeMap::new();
    for need in &context.needs {
        for offer in stored_overlapping_offers_for_need(store, need)? {
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
    Ok(ProjectionContext::from_matches(matched))
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
) -> Result<usize, String> {
    let mut inserted = 0usize;
    for need in &delta.added_needs {
        inserted += insert_pending_projection_from_select_in_tx(
            store,
            &overlapping_offers_for_need_select(need),
            "need",
        )?;
    }
    for offer in &delta.added_offers {
        inserted += insert_pending_projection_from_select_in_tx(
            store,
            &overlapping_needs_for_offer_select(offer),
            "offer",
        )?;
    }
    Ok(inserted)
}

fn overlapping_offers_for_need_select(need: &ContextNeed) -> insert_select::Select {
    let scope_key = scope_key(&need.scope);
    insert_select::Select::new(
        r#"
        SELECT :need_owner AS owner
        WHERE EXISTS (
            SELECT 1
            FROM context_edges
            WHERE direction = 'offer'
              AND role = :role
              AND scope_key = :scope_key
              AND start_key <= :need_end
              AND end_key >= :need_start
        )
        "#,
        &[CONTEXT_EDGES],
        vec![
            insert_select::Param::bytes(":need_owner", need.owner),
            insert_select::Param::text(":role", need.role.as_str()),
            insert_select::Param::bytes(":scope_key", scope_key),
            insert_select::Param::bytes(":need_start", need.start_key.as_bytes()),
            insert_select::Param::bytes(":need_end", need.end_key.as_bytes()),
        ],
    )
}

fn overlapping_needs_for_offer_select(offer: &ContextOffer) -> insert_select::Select {
    let scope_key = scope_key(&offer.scope);
    insert_select::Select::new(
        r#"
        SELECT n.owner
        FROM context_edges n
        JOIN local_fact_admissions a ON a.fact_id = n.owner
        WHERE n.direction = 'need'
          AND n.role = :role
          AND n.scope_key = :scope_key
          AND n.start_key <= :offer_end
          AND n.end_key >= :offer_start
        ORDER BY a.received_at, n.owner
        "#,
        &[CONTEXT_EDGES, LOCAL_FACT_ADMISSIONS],
        vec![
            insert_select::Param::text(":role", offer.role.as_str()),
            insert_select::Param::bytes(":scope_key", scope_key),
            insert_select::Param::bytes(":offer_start", offer.start_key.as_bytes()),
            insert_select::Param::bytes(":offer_end", offer.end_key.as_bytes()),
        ],
    )
}

fn insert_pending_projection_from_select_in_tx(
    store: &Store,
    select: &insert_select::Select,
    edge_kind: &str,
) -> Result<usize, String> {
    let owner_rows = insert_select::select_first_column_bytes_in_tx(store, select)
        .map_err(|err| format!("wake {edge_kind} from SELECT: {err}"))?;
    let mut changed = 0usize;
    for owner in owner_rows {
        let owner = fact_id_column(owner, "owner")
            .map_err(|err| format!("wake {edge_kind} from SELECT: {err}"))?;
        changed += mark_projection_pending_in_tx(store, owner)
            .map_err(|err| format!("wake {edge_kind} from SELECT: {err}"))?;
    }
    Ok(changed)
}
