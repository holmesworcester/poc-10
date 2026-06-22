//! Standing context rows, projection context assembly, and context wake fanout.
//!
//! Context is core's dependency surface between facts. A projector can say
//! "this fact needs this role, scope, and exact key before it can finish" by
//! emitting a `ContextNeed`, or "this fact provides this scalar value for
//! matching needs" by emitting a `ContextOffer`. Core does not know the
//! protocol meaning of those relationships. It matches only stable role/scope
//! partitions plus exact-key or range-offer coverage.
//!
//! This module is where that model becomes SQL. The public vocabulary lives in
//! `core::context`: needs, offers, roles, keys, scopes, and normalized
//! `ContextSet`s. Protocol projectors produce those sets. The projection
//! step calls this file to assemble matched `ProjectionContext`, replace stored
//! needs, append stored offers, compare output with current standing context,
//! and fan out wakeups to facts that may now make progress.
//!
//! Exact needs and exact/range offers are stored separately. The `owner` column
//! is always the fact whose projection emitted the row. For offers, core stores
//! a scalar value and a content-derived offer id; matched projection context is
//! hydrated from that offer row, not from retained fact bytes. Needs are current
//! subscriptions: when a fact projects again, its new output replaces the old
//! need rows it owned. Offers are append-only evidence: once inserted, an offer
//! remains until the owner fact is purged.
//!
//! The invariant is replacement needs plus append-only offers. Projection
//! output is the complete need set and new offer set for one fact, and wake
//! fanout considers only added rows from the resulting delta. If protocol
//! semantics change, keep the generic overlap query here and change the
//! domain-owned key encoders/validators.

use crate::core::context::{
    context_set_additions, scope_key, ContextKey, ContextNeed, ContextOffer, ContextOfferId,
    ContextSet, ContextSetAdditions, Role,
};
use crate::core::db::Db;
use crate::core::facts::{Fact, FactId, FactScope, ScopeKind};
use crate::core::schema::CONTEXT_NEEDS;
use crate::core::wire::{Reader, WireError};
use rusqlite::{params, OptionalExtension};
use std::collections::BTreeSet;

use super::{
    delete_rows_by_owner_in_tx, insert_pending_owner_in_tx, perf, sqlite_u64, u64_column,
    MatchedContext, ProjectionContext,
};

struct StoredContextOffer {
    offer: ContextOffer,
    owner_scope: FactScope,
    owner_received_at: u64,
}

fn is_exact_range(start: &ContextKey, end: &ContextKey) -> bool {
    start == end
}

/// Load a fact's standing context: the needs and offers it currently owns.
pub(crate) fn stored_context_for_owner(store: &Db, owner: &FactId) -> Result<ContextSet, String> {
    perf::measure_result("context_stored_context_owner", || {
        Ok(ContextSet {
            needs: stored_needs_for_owner(store, owner)?,
            offers: stored_offers_for_owner(store, owner)?,
        }
        .normalized())
    })
}

/// Replace this fact's standing needs, append its offers, and report additions.
///
/// Needs are current subscriptions, so each successful durable projection
/// replaces the owner's need rows. Offers are durable evidence emitted by an
/// immutable fact, so they are inserted idempotently and remain until the fact
/// is purged. The additions are computed against current stored context inside
/// the commit transaction rather than against queue-time projection state.
pub(crate) fn replace_context_for_owner_in_tx(
    store: &Db,
    owner_fact: &Fact,
    context: &ContextSet,
) -> rusqlite::Result<ContextSetAdditions> {
    let owner = owner_fact.id;
    let previous =
        stored_context_for_owner(store, &owner).map_err(rusqlite::Error::InvalidParameterName)?;
    let additions = context_set_additions(&previous, context);

    delete_rows_by_owner_in_tx(store, CONTEXT_NEEDS, owner)?;
    for need in &context.needs {
        insert_context_need_in_tx(store, need)?;
    }
    for offer in &context.offers {
        insert_context_offer_with_owner_metadata_in_tx(
            store,
            offer,
            &owner_fact.scope,
            owner_fact.timestamp,
        )?;
    }
    Ok(additions)
}

pub(crate) fn insert_context_need_in_tx(store: &Db, need: &ContextNeed) -> rusqlite::Result<bool> {
    insert_context_need_row_in_tx(store, need)
}

/// Insert one standing offer row inside the projection transaction.
#[cfg(test)]
pub(crate) fn insert_context_offer_in_tx(
    store: &Db,
    offer: &ContextOffer,
) -> rusqlite::Result<bool> {
    insert_context_offer_with_owner_metadata_in_tx(store, offer, &offer.scope, 0)
}

fn insert_context_offer_with_owner_metadata_in_tx(
    store: &Db,
    offer: &ContextOffer,
    owner_scope: &FactScope,
    owner_received_at: u64,
) -> rusqlite::Result<bool> {
    if offer.is_exact() {
        insert_exact_context_offer_in_tx(store, offer, owner_scope, owner_received_at)
    } else {
        insert_range_context_offer_in_tx(store, offer, owner_scope, owner_received_at)
    }
}

#[cfg(test)]
pub(crate) fn insert_context_offer_for_test(
    store: &Db,
    offer: &ContextOffer,
) -> Result<(), String> {
    store
        .write_transaction(|tx| insert_context_offer_in_tx(tx, offer).map(|_| ()))
        .map_err(|err| format!("insert context offer: {err}"))
}

pub(crate) fn delete_pending_matches_for_offer_owner_in_tx(
    store: &Db,
    owner: FactId,
) -> rusqlite::Result<usize> {
    store.conn().execute(
        "DELETE FROM pending_projection_matches
         WHERE offer_id IN (
             SELECT offer_id FROM context_exact_offers WHERE owner = ?1
             UNION
             SELECT offer_id FROM context_range_offers WHERE owner = ?1
         )",
        params![owner.as_slice()],
    )
}

/// Load context offers matching a single exact need key.
pub(super) fn stored_overlapping_offers_for_need(
    store: &Db,
    need: &ContextNeed,
) -> Result<Vec<ContextOffer>, String> {
    let scope_key = scope_key(&need.scope);
    let mut offers =
        exact_offers_for_key(store, need.role.as_str(), &scope_key, need.key.as_bytes())?;
    offers.extend(range_offers_covering_key(
        store,
        need.role.as_str(),
        &scope_key,
        need.key.as_bytes(),
    )?);
    offers.sort();
    offers.dedup();
    Ok(offers)
}

/// Load all needs owned by one fact.
fn stored_needs_for_owner(store: &Db, owner: &FactId) -> Result<Vec<ContextNeed>, String> {
    let mut needs = stored_needs_for_owner_rows(store, owner)?;
    needs.sort();
    needs.dedup();
    Ok(needs)
}

fn stored_needs_for_owner_rows(store: &Db, owner: &FactId) -> Result<Vec<ContextNeed>, String> {
    perf::measure_result("context_owner_needs", || {
        select_context_needs(
            store,
            r#"
    SELECT owner, role, scope_key, key
    FROM context_needs
    WHERE owner = :owner
    ORDER BY owner, role, scope_key, key
    "#,
            &[(":owner", bytes(owner))],
        )
    })
}

/// Load all offers owned by one fact.
fn stored_offers_for_owner(store: &Db, owner: &FactId) -> Result<Vec<ContextOffer>, String> {
    let mut offers = stored_exact_offers_for_owner(store, owner)?;
    offers.extend(stored_range_offers_for_owner(store, owner)?);
    offers.sort();
    offers.dedup();
    Ok(offers)
}

fn stored_exact_offers_for_owner(store: &Db, owner: &FactId) -> Result<Vec<ContextOffer>, String> {
    perf::measure_result("context_owner_exact_offers", || {
        select_exact_context_offers(
            store,
            r#"
    SELECT owner, role, scope_key, key, value
    FROM context_exact_offers
    WHERE owner = :owner
    ORDER BY owner, role, scope_key, key
    "#,
            &[(":owner", bytes(owner))],
        )
    })
}

fn stored_range_offers_for_owner(store: &Db, owner: &FactId) -> Result<Vec<ContextOffer>, String> {
    perf::measure_result("context_owner_range_offers", || {
        select_range_context_offers(
            store,
            r#"
    SELECT owner, role, scope_key, start_key, end_key, value
    FROM context_range_offers
    WHERE owner = :owner
    ORDER BY owner, role, scope_key, start_key, end_key
    "#,
            &[(":owner", bytes(owner))],
        )
    })
}

fn select_context_needs(
    store: &Db,
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

fn select_exact_context_offers(
    store: &Db,
    sql: &str,
    params: &[(&str, rusqlite::types::Value)],
) -> Result<Vec<ContextOffer>, String> {
    let mut stmt = store
        .conn()
        .prepare(sql)
        .map_err(|err| format!("load exact context offers: {err}"))?;
    bind_named_params(&mut stmt, params)
        .map_err(|err| format!("load exact context offers: {err}"))?;
    let rows = stmt
        .raw_query()
        .mapped(selected_exact_context_offer)
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("load exact context offers: {err}"))?;
    Ok(rows)
}

fn select_range_context_offers(
    store: &Db,
    sql: &str,
    params: &[(&str, rusqlite::types::Value)],
) -> Result<Vec<ContextOffer>, String> {
    let mut stmt = store
        .conn()
        .prepare(sql)
        .map_err(|err| format!("load range context offers: {err}"))?;
    bind_named_params(&mut stmt, params)
        .map_err(|err| format!("load range context offers: {err}"))?;
    let rows = stmt
        .raw_query()
        .mapped(selected_range_context_offer)
        .collect::<rusqlite::Result<Vec<_>>>()
        .map_err(|err| format!("load range context offers: {err}"))?;
    Ok(rows)
}

fn insert_context_need_row_in_tx(store: &Db, need: &ContextNeed) -> rusqlite::Result<bool> {
    let scope_key = scope_key(&need.scope);
    store
        .conn()
        .execute(
            "INSERT OR IGNORE INTO context_needs
            (owner, role, scope_key, key)
         VALUES (?1, ?2, ?3, ?4)",
            params![
                need.owner.as_slice(),
                need.role.as_str(),
                scope_key.as_slice(),
                need.key.as_bytes()
            ],
        )
        .map(|count| count > 0)
}

fn insert_exact_context_offer_in_tx(
    store: &Db,
    offer: &ContextOffer,
    owner_scope: &FactScope,
    owner_received_at: u64,
) -> rusqlite::Result<bool> {
    let owner_scope_key = scope_key(owner_scope);
    let owner_received_at = sqlite_u64(owner_received_at, "context offer owner received_at")?;
    let scope_key = scope_key(&offer.scope);
    let offer_id = offer.id();
    store
        .conn()
        .execute(
            "INSERT OR IGNORE INTO context_exact_offers
            (offer_id,
             owner,
             owner_scope_key,
             owner_received_at,
             role,
             scope_key,
             key,
             value)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                offer_id.as_slice(),
                offer.owner.as_slice(),
                owner_scope_key.as_slice(),
                owner_received_at,
                offer.role.as_str(),
                scope_key.as_slice(),
                offer.start_key.as_bytes(),
                offer.value.as_slice(),
            ],
        )
        .map(|count| count > 0)
}

fn insert_range_context_offer_in_tx(
    store: &Db,
    offer: &ContextOffer,
    owner_scope: &FactScope,
    owner_received_at: u64,
) -> rusqlite::Result<bool> {
    let owner_scope_key = scope_key(owner_scope);
    let owner_received_at = sqlite_u64(owner_received_at, "context offer owner received_at")?;
    let scope_key = scope_key(&offer.scope);
    let offer_id = offer.id();
    store
        .conn()
        .execute(
            "INSERT OR IGNORE INTO context_range_offers
            (offer_id,
             owner,
             owner_scope_key,
             owner_received_at,
             role,
             scope_key,
             start_key,
             end_key,
             value)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                offer_id.as_slice(),
                offer.owner.as_slice(),
                owner_scope_key.as_slice(),
                owner_received_at,
                offer.role.as_str(),
                scope_key.as_slice(),
                offer.start_key.as_bytes(),
                offer.end_key.as_bytes(),
                offer.value.as_slice(),
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
        key: ContextKey::from_bytes(row.get::<_, Vec<u8>>(3)?),
    })
}

/// Decode one persisted offer row back into the public context type.
fn selected_exact_context_offer(row: &rusqlite::Row<'_>) -> rusqlite::Result<ContextOffer> {
    let key = ContextKey::from_bytes(row.get::<_, Vec<u8>>(3)?);
    Ok(ContextOffer {
        owner: fact_id_column(row.get::<_, Vec<u8>>(0)?, "owner")?,
        role: Role::new(row.get::<_, String>(1)?).map_err(rusqlite::Error::InvalidParameterName)?,
        scope: decode_scope_key(&row.get::<_, Vec<u8>>(2)?)
            .map_err(rusqlite::Error::InvalidParameterName)?,
        start_key: key.clone(),
        end_key: key,
        value: row.get::<_, Vec<u8>>(4)?,
    })
}

fn selected_range_context_offer(row: &rusqlite::Row<'_>) -> rusqlite::Result<ContextOffer> {
    Ok(ContextOffer {
        owner: fact_id_column(row.get::<_, Vec<u8>>(0)?, "owner")?,
        role: Role::new(row.get::<_, String>(1)?).map_err(rusqlite::Error::InvalidParameterName)?,
        scope: decode_scope_key(&row.get::<_, Vec<u8>>(2)?)
            .map_err(rusqlite::Error::InvalidParameterName)?,
        start_key: ContextKey::from_bytes(row.get::<_, Vec<u8>>(3)?),
        end_key: ContextKey::from_bytes(row.get::<_, Vec<u8>>(4)?),
        value: row.get::<_, Vec<u8>>(5)?,
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

fn context_offer_id_column(bytes: Vec<u8>, name: &str) -> rusqlite::Result<ContextOfferId> {
    bytes.try_into().map_err(|_| {
        rusqlite::Error::InvalidParameterName(format!(
            "context SQL column {name} is not a context offer id"
        ))
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

/// Load context matches already attached as pending projection input.
///
/// Context fanout records these rows when it queues the owner. Loading a
/// pending item therefore does not have to search standing context for the
/// owner's old needs before the first projector run.
pub(crate) fn pending_projection_input_context_for_owner(
    store: &Db,
    owner: &FactId,
) -> Result<ProjectionContext, String> {
    let pairs = perf::measure_result("context_pending_matches_select", || {
        let mut stmt = store
            .conn()
            .prepare(
                r#"
            SELECT need_role,
                   need_scope_key,
                   need_key,
                   offer_id
            FROM pending_projection_matches
            WHERE owner = ?1
            ORDER BY
                need_role,
                need_scope_key,
                need_key,
                offer_id
            "#,
            )
            .map_err(|err| format!("load pending projection matches: {err}"))?;
        let rows = stmt
            .query_map(params![owner.as_slice()], |row| {
                selected_pending_projection_match(row, owner)
            })
            .map_err(|err| format!("load pending projection matches: {err}"))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|err| format!("load pending projection matches: {err}"))
    })?;

    let mut matched = Vec::new();
    let mut seen = BTreeSet::new();
    for (need, offer_id) in pairs {
        let offer = stored_offer_by_id(store, &offer_id)?;
        push_stored_matched_context(&need, offer, &mut seen, &mut matched);
    }
    Ok(ProjectionContext::from_matches(matched))
}

/// Decode one pending match row into the need owned by `owner` and its offer id.
///
/// Pending match rows deliberately store only the matched need and offer id.
/// Loading the `ProjectionContext` later resolves the offer id to its stored
/// scalar value; it does not load the offering fact bytes.
fn selected_pending_projection_match(
    row: &rusqlite::Row<'_>,
    owner: &FactId,
) -> rusqlite::Result<(ContextNeed, ContextOfferId)> {
    let role =
        Role::new(row.get::<_, String>(0)?).map_err(rusqlite::Error::InvalidParameterName)?;
    let scope = decode_scope_key(&row.get::<_, Vec<u8>>(1)?)
        .map_err(rusqlite::Error::InvalidParameterName)?;
    let need = ContextNeed {
        owner: *owner,
        role: role.clone(),
        scope: scope.clone(),
        key: ContextKey::from_bytes(row.get::<_, Vec<u8>>(2)?),
    };
    let offer_id = context_offer_id_column(row.get::<_, Vec<u8>>(3)?, "offer_id")?;
    Ok((need, offer_id))
}

fn stored_offer_by_id(store: &Db, offer_id: &ContextOfferId) -> Result<StoredContextOffer, String> {
    if let Some(offer) = select_exact_stored_context_offer_by_id(store, offer_id)? {
        return Ok(offer);
    }
    if let Some(offer) = select_range_stored_context_offer_by_id(store, offer_id)? {
        return Ok(offer);
    }
    Err("pending context match references unknown offer".to_string())
}

fn select_exact_stored_context_offer_by_id(
    store: &Db,
    offer_id: &ContextOfferId,
) -> Result<Option<StoredContextOffer>, String> {
    store
        .conn()
        .query_row(
            r#"
    SELECT owner, owner_scope_key, owner_received_at, role, scope_key, key, value
    FROM context_exact_offers
    WHERE offer_id = ?1
    LIMIT 1
    "#,
            params![offer_id.as_slice()],
            selected_exact_stored_context_offer,
        )
        .optional()
        .map_err(|err| format!("load exact context offer: {err}"))
}

fn select_range_stored_context_offer_by_id(
    store: &Db,
    offer_id: &ContextOfferId,
) -> Result<Option<StoredContextOffer>, String> {
    store
        .conn()
        .query_row(
            r#"
    SELECT owner, owner_scope_key, owner_received_at, role, scope_key, start_key, end_key, value
    FROM context_range_offers
    WHERE offer_id = ?1
    LIMIT 1
    "#,
            params![offer_id.as_slice()],
            selected_range_stored_context_offer,
        )
        .optional()
        .map_err(|err| format!("load range context offer: {err}"))
}

fn selected_exact_stored_context_offer(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<StoredContextOffer> {
    let key = ContextKey::from_bytes(row.get::<_, Vec<u8>>(5)?);
    Ok(StoredContextOffer {
        offer: ContextOffer {
            owner: fact_id_column(row.get::<_, Vec<u8>>(0)?, "owner")?,
            role: Role::new(row.get::<_, String>(3)?)
                .map_err(rusqlite::Error::InvalidParameterName)?,
            scope: decode_scope_key(&row.get::<_, Vec<u8>>(4)?)
                .map_err(rusqlite::Error::InvalidParameterName)?,
            start_key: key.clone(),
            end_key: key,
            value: row.get::<_, Vec<u8>>(6)?,
        },
        owner_scope: decode_scope_key(&row.get::<_, Vec<u8>>(1)?)
            .map_err(rusqlite::Error::InvalidParameterName)?,
        owner_received_at: u64_column(row.get::<_, i64>(2)?, "owner_received_at")?,
    })
}

fn selected_range_stored_context_offer(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<StoredContextOffer> {
    Ok(StoredContextOffer {
        offer: ContextOffer {
            owner: fact_id_column(row.get::<_, Vec<u8>>(0)?, "owner")?,
            role: Role::new(row.get::<_, String>(3)?)
                .map_err(rusqlite::Error::InvalidParameterName)?,
            scope: decode_scope_key(&row.get::<_, Vec<u8>>(4)?)
                .map_err(rusqlite::Error::InvalidParameterName)?,
            start_key: ContextKey::from_bytes(row.get::<_, Vec<u8>>(5)?),
            end_key: ContextKey::from_bytes(row.get::<_, Vec<u8>>(6)?),
            value: row.get::<_, Vec<u8>>(7)?,
        },
        owner_scope: decode_scope_key(&row.get::<_, Vec<u8>>(1)?)
            .map_err(rusqlite::Error::InvalidParameterName)?,
        owner_received_at: u64_column(row.get::<_, i64>(2)?, "owner_received_at")?,
    })
}

/// Add a matched pair and expose the stored offer value as legacy payload bytes.
fn push_stored_matched_context(
    need: &ContextNeed,
    stored: StoredContextOffer,
    seen: &mut BTreeSet<(ContextNeed, ContextOffer)>,
    matched: &mut Vec<MatchedContext>,
) {
    let offer = stored.offer;
    if !seen.insert((need.clone(), offer.clone())) {
        return;
    }
    let payload = Fact {
        id: offer.owner,
        scope: stored.owner_scope,
        timestamp: stored.owner_received_at,
        bytes: offer.value.clone(),
    };
    matched.push(MatchedContext {
        need: need.clone(),
        offer,
        payload,
    });
}

/// Queue and record matches for owners woken by newly added context rows.
///
/// Removals do not wake projection. A projector that stops needing context has
/// already run; dependent facts wake only when a new need can now be satisfied
/// or a new offer may satisfy existing needs. An owner is woken only when at
/// least one overlapping edge exists; for each such owner this queues it pending
/// and records every match its standing needs currently have. Recording from
/// stored needs is idempotent, so distinct overlaps for the same owner collapse
/// to one queue-and-record pass.
pub(crate) fn wake_context_matches_in_tx(
    store: &Db,
    additions: &ContextSetAdditions,
) -> Result<usize, String> {
    let owners = perf::measure_result("context_wake_find_owners", || {
        let mut owners = BTreeSet::new();
        for need in &additions.needs {
            let has_offer = perf::measure_result("context_wake_need_offer_probe", || {
                stored_overlapping_offers_for_need(store, need).map(|offers| !offers.is_empty())
            })?;
            if has_offer {
                owners.insert(need.owner);
            }
        }
        for offer in &additions.offers {
            for need in perf::measure_result("context_wake_offer_need_probe", || {
                stored_overlapping_needs_for_offer(store, offer)
            })? {
                owners.insert(need.owner);
            }
        }
        Ok::<_, String>(owners)
    })?;

    perf::measure_result("context_wake_record_owners", || {
        let mut changed = 0usize;
        for owner in owners {
            let queued = insert_pending_owner_in_tx(store, owner)
                .map_err(|err| format!("queue pending projection input: {err}"))?;
            let recorded = record_pending_context_inputs_for_stored_needs_in_tx(store, owner)?;
            changed += usize::from(queued > 0 || recorded > 0);
        }
        Ok(changed)
    })
}

fn stored_overlapping_needs_for_offer(
    store: &Db,
    offer: &ContextOffer,
) -> Result<Vec<ContextNeed>, String> {
    let scope_key = scope_key(&offer.scope);
    let mut needs = if is_exact_range(&offer.start_key, &offer.end_key) {
        needs_for_key(
            store,
            offer.role.as_str(),
            &scope_key,
            offer.start_key.as_bytes(),
        )?
    } else {
        needs_in_offer_range(
            store,
            offer.role.as_str(),
            &scope_key,
            offer.start_key.as_bytes(),
            offer.end_key.as_bytes(),
        )?
    };
    needs.sort();
    needs.dedup();
    Ok(needs)
}

fn exact_offers_for_key(
    store: &Db,
    role: &str,
    scope_key: &[u8],
    key: &[u8],
) -> Result<Vec<ContextOffer>, String> {
    perf::measure_result("context_exact_offers_key", || {
        select_exact_context_offers(
            store,
            r#"
    SELECT owner, role, scope_key, key, value
    FROM context_exact_offers
    WHERE role = :role
      AND scope_key = :scope_key
      AND key = :key
    ORDER BY owner, key
    "#,
            &[
                (":role", text(role)),
                (":scope_key", bytes(scope_key)),
                (":key", bytes(key)),
            ],
        )
    })
}

fn needs_for_key(
    store: &Db,
    role: &str,
    scope_key: &[u8],
    key: &[u8],
) -> Result<Vec<ContextNeed>, String> {
    perf::measure_result("context_needs_key", || {
        select_context_needs(
            store,
            r#"
    SELECT owner, role, scope_key, key
    FROM context_needs
    WHERE role = :role
      AND scope_key = :scope_key
      AND key = :key
    ORDER BY owner, key
    "#,
            &[
                (":role", text(role)),
                (":scope_key", bytes(scope_key)),
                (":key", bytes(key)),
            ],
        )
    })
}

fn needs_in_offer_range(
    store: &Db,
    role: &str,
    scope_key: &[u8],
    start_key: &[u8],
    end_key: &[u8],
) -> Result<Vec<ContextNeed>, String> {
    perf::measure_result("context_needs_in_offer_range", || {
        select_context_needs(
            store,
            r#"
    SELECT owner, role, scope_key, key
    FROM context_needs
    WHERE role = :role
      AND scope_key = :scope_key
      AND key >= :start_key
      AND key <= :end_key
    ORDER BY owner, key
    "#,
            &[
                (":role", text(role)),
                (":scope_key", bytes(scope_key)),
                (":start_key", bytes(start_key)),
                (":end_key", bytes(end_key)),
            ],
        )
    })
}

fn range_offers_covering_key(
    store: &Db,
    role: &str,
    scope_key: &[u8],
    key: &[u8],
) -> Result<Vec<ContextOffer>, String> {
    perf::measure_result("context_range_offers_covering_key", || {
        select_range_context_offers(
            store,
            r#"
    SELECT owner, role, scope_key, start_key, end_key, value
    FROM context_range_offers
    WHERE role = :role
      AND scope_key = :scope_key
      AND start_key <= :key
      AND end_key >= :key
    ORDER BY owner, start_key, end_key
    "#,
            &[
                (":role", text(role)),
                (":scope_key", bytes(scope_key)),
                (":key", bytes(key)),
            ],
        )
    })
}

/// Record pending context inputs for every standing need an owner currently holds.
///
/// Used both by context wake fanout and by direct queueing paths (due time
/// wakes, duplicate fact admission) that attach context to an owner's existing
/// needs. Idempotent: every input row is an `INSERT OR IGNORE`.
pub(super) fn record_pending_context_inputs_for_stored_needs_in_tx(
    store: &Db,
    owner: FactId,
) -> Result<usize, String> {
    perf::measure_result("context_record_pending_inputs_for_owner", || {
        let mut changed = 0usize;
        for need in stored_needs_for_owner(store, &owner)? {
            for offer in stored_overlapping_offers_for_need(store, &need)? {
                changed += record_pending_context_input_in_tx(store, &need, &offer)?;
            }
        }
        Ok(changed)
    })
}

fn record_pending_context_input_in_tx(
    store: &Db,
    need: &ContextNeed,
    offer: &ContextOffer,
) -> Result<usize, String> {
    if need.role != offer.role || need.scope != offer.scope {
        return Err("pending projection context input role/scope mismatch".to_string());
    }
    let scope_key = scope_key(&need.scope);
    let offer_id = offer.id();
    perf::measure_result("context_pending_match_insert", || {
        store
            .conn()
            .execute(
                "INSERT OR IGNORE INTO pending_projection_matches
                (owner,
                 need_role,
                 need_scope_key,
                 need_key,
                 offer_id)
             VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    need.owner.as_slice(),
                    need.role.as_str(),
                    scope_key.as_slice(),
                    need.key.as_bytes(),
                    offer_id.as_slice(),
                ],
            )
            .map_err(|err| format!("record pending projection match: {err}"))
    })
}
