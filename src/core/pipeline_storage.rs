//! Durable storage and row codec for the runtime
//! [`pipeline`](crate::core::pipeline).
//!
//! [`pipeline`](crate::core::pipeline) decides *what* the runtime does with
//! facts, context, and intents; this module decides *how* that state is stored
//! in SQLite. It owns three things:
//!
//! - **Durable mutations** — [`insert_fact_and_pending_in_tx`],
//!   [`purge_fact_in_tx`], [`record_intent_in_tx`], and the pending-queue
//!   helpers: the in-transaction building blocks the pipeline commits with.
//! - **Context reads** — loading a fact's standing context back out of SQLite
//!   and matching needs against offers ([`stored_matching_context`],
//!   [`stored_context_matches`]).
//! - **Row encoding** — turning facts, context needs and offers, time wakes,
//!   and intents into rows and back: the `*_row` builders, the `typed_*`
//!   encoders, and the `decode_*` decoders.
//!
//! # Row model
//!
//! Every runtime row is a key/value pair of [`wire`](crate::core::wire)-encoded
//! bytes. Most rows carry all of their fields in the *key* and leave the value
//! empty, so the store can look a row up by any named column of its key. Facts
//! and intents are the exception: they hold a variable-length payload, which
//! lives in the value.

use crate::core::context::{
    ContextNeed, ContextOffer, ContextSet, ContextSetDelta, Role, Selector,
};
use crate::core::facts::{fact_id, Fact, FactId, FactScope, ScopeKind};
use crate::core::intents::{Intent, IntentKind, RowMutation, TableDelete};
use crate::core::matchers::{ContextMatch, ContextMatcher};
use crate::core::pipeline::{
    CONTEXT_NEEDS, CONTEXT_OFFERS, FACTS, INTENTS, PENDING_CONTEXT_CHANGES, PENDING_PROJECTION,
    PENDING_TIME_RANGES, TIME_WAKES,
};
use crate::core::projectors::{MatchedContext, ProjectionContext};
use crate::core::store::{ColumnValue, Store, TableName, TableRow};
use crate::core::wire::{Reader, WireError, Writer};
use std::collections::{BTreeMap, BTreeSet};

// === Matching helpers ===

/// Lookup key for exact context matching: a need and an offer match when their
/// role, scope, and selector are all equal.
pub(crate) type ExactContextKey = (Role, FactScope, Selector);

/// Build the [`ExactContextKey`] for a role/scope/selector triple.
pub(crate) fn exact_context_key(
    role: &Role,
    scope: &FactScope,
    selector: &Selector,
) -> ExactContextKey {
    (role.clone(), scope.clone(), selector.clone())
}

/// Roles served by exact selector matching rather than a custom matcher.
pub(crate) fn exact_matcher_roles(matchers: &[&dyn ContextMatcher]) -> BTreeSet<Role> {
    matchers
        .iter()
        .filter_map(|matcher| matcher.exact_selector_role().cloned())
        .collect()
}

/// Custom (non-exact) matchers whose role appears somewhere in `delta`.
///
/// Context matching only has to consult a custom matcher when the batch of
/// changes actually touches that matcher's role.
pub(crate) fn relevant_custom_matchers_for_delta<'a>(
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

// === Durable mutations ===

/// Insert a fact and mark it pending for projection.
///
/// Facts are immutable and content-addressed, so a fact that already exists is
/// left untouched. Returns whether the fact was newly inserted.
pub(crate) fn insert_fact_and_pending_in_tx(store: &Store, fact: &Fact) -> rusqlite::Result<bool> {
    if store.table_row(FACTS, &fact.id)?.is_some() {
        return Ok(false);
    }
    let inserted = store.insert_table_rows_in_tx(vec![fact_row(fact)])? > 0;
    if inserted {
        insert_pending_owner_in_tx(store, fact.id)?;
    }
    Ok(inserted)
}

/// Mark `owner` pending so the next projection pass (re)projects it.
pub(crate) fn insert_pending_owner_in_tx(store: &Store, owner: FactId) -> rusqlite::Result<usize> {
    store.insert_table_rows_in_tx(vec![TableRow {
        table: PENDING_PROJECTION,
        key: owner.to_vec(),
        value: Vec::new(),
    }])
}

/// Remove a fact and every durable row keyed to it.
///
/// Deletes the fact itself, its context needs and offers, its time wakes, any
/// pending context-change or time-range rows it owns, and its pending-projection
/// marker. Returns whether anything was actually removed.
pub(crate) fn purge_fact_in_tx(store: &Store, owner: FactId) -> rusqlite::Result<bool> {
    let mut changed = store.delete_table_rows_in_tx(FACTS, vec![owner.to_vec()])? > 0;
    for table in [
        CONTEXT_NEEDS,
        CONTEXT_OFFERS,
        TIME_WAKES,
        PENDING_CONTEXT_CHANGES,
        PENDING_TIME_RANGES,
    ] {
        changed |= delete_rows_owned_by(store, table, &owner)?;
    }
    changed |= store.delete_table_rows_in_tx(PENDING_PROJECTION, vec![owner.to_vec()])? > 0;
    Ok(changed)
}

/// Delete every row in `table` whose `owner` column equals `owner`.
///
/// This is the "remove all of one fact's rows from a side table" step that
/// [`purge_fact_in_tx`] repeats for each table. Returns whether any row matched.
fn delete_rows_owned_by(store: &Store, table: TableName, owner: &FactId) -> rusqlite::Result<bool> {
    let keys = store
        .table_rows_where(table, &[("owner", ColumnValue::Bytes(owner))])?
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    let removed = !keys.is_empty();
    store.delete_table_rows_in_tx(table, keys)?;
    Ok(removed)
}

/// Persist an intent, deduplicated by its idempotence key.
///
/// Returns whether the intent was newly recorded; an intent whose key already
/// exists is left in place.
pub(crate) fn record_intent_in_tx(store: &Store, intent: &Intent) -> rusqlite::Result<bool> {
    record_intent_in_table_in_tx(store, INTENTS, intent)
}

pub(crate) fn record_intent_in_table_in_tx(
    store: &Store,
    table: TableName,
    intent: &Intent,
) -> rusqlite::Result<bool> {
    let mut row = intent_row(intent);
    row.table = table;
    store
        .insert_table_rows_in_tx(vec![row])
        .map(|count| count > 0)
}

// === Row builders ===

/// Encode a fact as its [`FACTS`] row.
pub(crate) fn fact_row(fact: &Fact) -> TableRow {
    TableRow {
        table: FACTS,
        key: fact.id.to_vec(),
        value: typed_fact_value(fact),
    }
}

/// Encode a context need as its (key-only) [`CONTEXT_NEEDS`] row.
pub(crate) fn context_need_row(need: &ContextNeed) -> TableRow {
    TableRow {
        table: CONTEXT_NEEDS,
        key: typed_context_key(&need.owner, &need.role, &need.scope, &need.selector),
        value: Vec::new(),
    }
}

/// Encode a context offer as its (key-only) [`CONTEXT_OFFERS`] row.
pub(crate) fn context_offer_row(offer: &ContextOffer) -> TableRow {
    TableRow {
        table: CONTEXT_OFFERS,
        key: typed_context_key(&offer.owner, &offer.role, &offer.scope, &offer.selector),
        value: Vec::new(),
    }
}

/// Encode an intent as its [`INTENTS`] row.
pub(crate) fn intent_row(intent: &Intent) -> TableRow {
    TableRow {
        table: INTENTS,
        key: intent_row_key(intent),
        value: typed_intent_value(intent),
    }
}

// === Row mutations ===

/// Reject any row mutation targeting a table this runtime has not registered.
pub(crate) fn validate_row_mutations(
    mutations: &[RowMutation],
    allowed_tables: &[TableName],
) -> Result<(), String> {
    for mutation in mutations {
        validate_row_mutation_table(mutation, allowed_tables)?;
    }
    Ok(())
}

/// Split row mutations into inserts and deletes so a commit can apply them.
pub(crate) fn row_mutation_rows(
    mutations: &[RowMutation],
    allowed_tables: &[TableName],
) -> Result<(Vec<TableRow>, Vec<TableDelete>), String> {
    let mut rows = Vec::new();
    let mut deletes = Vec::<TableDelete>::new();
    for mutation in mutations {
        validate_row_mutation_table(mutation, allowed_tables)?;
        match mutation {
            RowMutation::PutRow(row) => rows.push(row.clone()),
            RowMutation::DeleteRow(delete) => deletes.push(delete.clone()),
        }
    }
    Ok((rows, deletes))
}

fn validate_row_mutation_table(
    mutation: &RowMutation,
    allowed_tables: &[TableName],
) -> Result<(), String> {
    let table = match mutation {
        RowMutation::PutRow(row) => row.table,
        RowMutation::DeleteRow(delete) => delete.table,
    };
    if allowed_tables.contains(&table) {
        Ok(())
    } else {
        Err(format!(
            "row mutation table {} is not registered",
            table.as_str()
        ))
    }
}

/// Adapt a `String` error into the [`rusqlite::Error`] a transaction closure
/// must return, so a non-SQL failure can still abort a commit.
pub(crate) fn sqlite_string_error(err: String) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(err)
}

/// `change_kind` tag stored in a [`PENDING_CONTEXT_CHANGES`] key for an added
/// need (versus [`CONTEXT_CHANGE_OFFER`]).
const CONTEXT_CHANGE_NEED: u64 = 0;
/// `change_kind` tag stored in a [`PENDING_CONTEXT_CHANGES`] key for an added
/// offer (versus [`CONTEXT_CHANGE_NEED`]).
const CONTEXT_CHANGE_OFFER: u64 = 1;

/// Encode every added need and offer in `delta` as [`PENDING_CONTEXT_CHANGES`]
/// rows for the pipeline's context-matching stage to consume later.
pub(crate) fn pending_context_change_rows(delta: &ContextSetDelta) -> Vec<TableRow> {
    delta
        .added_needs
        .iter()
        .map(|need| {
            pending_context_change_row(
                &need.owner,
                CONTEXT_CHANGE_NEED,
                &need.role,
                &need.scope,
                &need.selector,
            )
        })
        .chain(delta.added_offers.iter().map(|offer| {
            pending_context_change_row(
                &offer.owner,
                CONTEXT_CHANGE_OFFER,
                &offer.role,
                &offer.scope,
                &offer.selector,
            )
        }))
        .collect()
}

// === Reading context from the store ===

/// Load a fact's standing context — the needs and offers it currently owns.
pub(crate) fn stored_context_for_owner(
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
///
/// This is the input context handed to a projector. For every need in
/// `context`, matching offers are resolved through exact selector matching or
/// the relevant custom matcher, and each match is returned with the offering
/// fact's payload attached.
pub(crate) fn stored_matching_context(
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
///
/// Given a batch of added needs and offers, return every [`ContextMatch`] that
/// custom matchers report. Exact selector wake fanout lives in
/// `pipeline::context_wake` as SQL over the declared context tables.
pub(crate) fn stored_context_matches(
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

/// Load the context needs owned by one fact.
fn stored_needs_for_owner(store: &Store, owner: &FactId) -> Result<Vec<ContextNeed>, String> {
    load_context_needs_from_rows(
        store
            .table_rows_where(CONTEXT_NEEDS, &[("owner", ColumnValue::Bytes(owner))])
            .map_err(|err| format!("load context needs: {err}"))?,
    )
}

/// Load the context offers owned by one fact.
fn stored_offers_for_owner(store: &Store, owner: &FactId) -> Result<Vec<ContextOffer>, String> {
    load_context_offers_from_rows(
        store
            .table_rows_where(CONTEXT_OFFERS, &[("owner", ColumnValue::Bytes(owner))])
            .map_err(|err| format!("load context offers: {err}"))?,
    )
}

/// Bulk-load the exact-keyed offers that could satisfy `needs`, grouped by
/// [`ExactContextKey`]. One query per (role, scope) keeps matching batched.
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
        let selector_values = selectors
            .iter()
            .map(|selector| ColumnValue::Bytes(selector.as_slice()))
            .collect::<Vec<_>>();
        for offer in load_context_offers_from_rows(
            store
                .table_rows_where_in(
                    CONTEXT_OFFERS,
                    &[
                        ("role", ColumnValue::Text(role.as_str())),
                        ("scope_key", ColumnValue::Bytes(&scope_key)),
                    ],
                    "selector",
                    &selector_values,
                )
                .map_err(|err| format!("load exact context offers: {err}"))?,
        )? {
            out.entry(exact_context_key(
                &offer.role,
                &offer.scope,
                &offer.selector,
            ))
            .or_default()
            .push(offer);
        }
    }
    Ok(out)
}

/// Append one deduplicated need/offer match, resolving the offering fact so the
/// projector receives the payload alongside the match.
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

/// Load every context need stored for one (role, scope).
fn stored_needs_for_role_scope(
    store: &Store,
    role: &Role,
    scope: &FactScope,
) -> Result<Vec<ContextNeed>, String> {
    load_context_needs_from_rows(
        store
            .table_rows_where(
                CONTEXT_NEEDS,
                &[
                    ("role", ColumnValue::Text(role.as_str())),
                    ("scope_key", ColumnValue::Bytes(&scope_key(scope))),
                ],
            )
            .map_err(|err| format!("load context needs: {err}"))?,
    )
}

/// Load every context offer stored for one (role, scope).
fn stored_offers_for_role_scope(
    store: &Store,
    role: &Role,
    scope: &FactScope,
) -> Result<Vec<ContextOffer>, String> {
    load_context_offers_from_rows(
        store
            .table_rows_where(
                CONTEXT_OFFERS,
                &[
                    ("role", ColumnValue::Text(role.as_str())),
                    ("scope_key", ColumnValue::Bytes(&scope_key(scope))),
                ],
            )
            .map_err(|err| format!("load context offers: {err}"))?,
    )
}

/// Decode a batch of raw [`CONTEXT_NEEDS`] rows.
fn load_context_needs_from_rows(rows: Vec<(Vec<u8>, Vec<u8>)>) -> Result<Vec<ContextNeed>, String> {
    rows.into_iter()
        .map(|(key, value)| decode_context_need_row(&key, &value))
        .collect()
}

/// Decode a batch of raw [`CONTEXT_OFFERS`] rows.
fn load_context_offers_from_rows(
    rows: Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<Vec<ContextOffer>, String> {
    rows.into_iter()
        .map(|(key, value)| decode_context_offer_row(&key, &value))
        .collect()
}

// === Encoding rows ===

/// Key layout shared by [`CONTEXT_NEEDS`] and [`CONTEXT_OFFERS`] rows:
/// `owner ++ role ++ scope ++ selector`.
fn typed_context_key(
    owner: &FactId,
    role: &Role,
    scope: &FactScope,
    selector: &Selector,
) -> Vec<u8> {
    encoded_row(|key| {
        key.fixed(owner);
        key.string_u32be(role.as_str())
            .expect("context role fits u32");
        key.bytes_u32be(&scope_key(scope))
            .expect("scope key fits u32");
        key.bytes_u32be(selector.as_bytes())
            .expect("selector fits u32");
    })
}

/// Encode one added need or offer as a [`PENDING_CONTEXT_CHANGES`] row.
///
/// `change_kind` is [`CONTEXT_CHANGE_NEED`] or [`CONTEXT_CHANGE_OFFER`]; it sits
/// in the key right after the owner so that a need and an offer with otherwise
/// identical fields remain distinct rows.
fn pending_context_change_row(
    owner: &FactId,
    change_kind: u64,
    role: &Role,
    scope: &FactScope,
    selector: &Selector,
) -> TableRow {
    let key = encoded_row(|key| {
        key.fixed(owner);
        key.u64be(change_kind);
        key.string_u32be(role.as_str())
            .expect("context role fits u32");
        key.bytes_u32be(&scope_key(scope))
            .expect("scope key fits u32");
        key.bytes_u32be(selector.as_bytes())
            .expect("selector fits u32");
    });
    TableRow {
        table: PENDING_CONTEXT_CHANGES,
        key,
        value: Vec::new(),
    }
}

/// Encode a [`FactScope`] into the bytes used as a row's `scope_key` column.
pub(crate) fn scope_key(scope: &FactScope) -> Vec<u8> {
    let mut out = Writer::new();
    encode_scope(&mut out, scope);
    out.finish()
}

/// Key layout for an [`INTENTS`] row: `kind ++ idempotence-key`. Two intents
/// collide here exactly when they are idempotent duplicates of each other.
pub(crate) fn intent_row_key(intent: &Intent) -> Vec<u8> {
    encoded_row(|key| {
        key.string_u32be(intent.kind.as_str())
            .expect("intent kind fits u32");
        key.bytes_u32be(&intent.key)
            .expect("intent idempotence key fits u32");
    })
}

/// Encode the value half of a [`FACTS`] row: scope columns, timestamp, payload.
fn typed_fact_value(fact: &Fact) -> Vec<u8> {
    encoded_row(|out| {
        match &fact.scope {
            FactScope::Global => write_fact_scope_columns(out, "global", "", &EMPTY_FACT_ID),
            FactScope::Local => write_fact_scope_columns(out, "local", "", &EMPTY_FACT_ID),
            FactScope::Scoped { kind, id } => {
                write_fact_scope_columns(out, "scoped", kind.as_str(), id)
            }
        }
        out.u64be(fact.timestamp);
        out.bytes_u32be(&fact.bytes).expect("fact bytes fit u32");
    })
}

/// Encode the value half of an [`INTENTS`] row: payload bytes.
fn typed_intent_value(intent: &Intent) -> Vec<u8> {
    encoded_row(|out| {
        out.bytes_u32be(&intent.payload)
            .expect("intent payload fits u32");
    })
}

// === Reading and decoding rows ===

/// Load a fact by id, returning `None` when no such fact is stored.
pub fn persisted_fact(store: &Store, id: &FactId) -> Result<Option<Fact>, String> {
    store
        .table_row(FACTS, id)
        .map_err(|err| format!("load fact row: {err}"))?
        .map(|value| decode_fact_row(id, &value))
        .transpose()
}

/// Load every stored fact.
pub fn persisted_facts(store: &Store) -> Result<Vec<Fact>, String> {
    store
        .table_rows(FACTS)
        .map_err(|err| format!("load fact rows: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_fact_row(&key, &value))
        .collect()
}

/// Load a fact's standing context, returning `None` when it has none.
pub fn persisted_context(store: &Store, owner: &FactId) -> Result<Option<ContextSet>, String> {
    let context = stored_context_for_owner(store, owner)?;
    if context.needs.is_empty() && context.offers.is_empty() {
        Ok(None)
    } else {
        Ok(Some(context))
    }
}

/// Decode a [`FACTS`] row, checking the key matches the content hash of the
/// payload bytes.
pub(crate) fn decode_fact_row(key: &[u8], value: &[u8]) -> Result<Fact, String> {
    let id = decode_fact_id(key)?;
    let mut reader = Reader::new(value);
    let scope_tag = reader.string_u32be().row()?;
    let scope_kind = reader.string_u32be().row()?;
    let scope_id = reader.array::<32>().row()?;
    let scope = decode_fact_scope_columns(&scope_tag, &scope_kind, &scope_id)?;
    let timestamp = reader.u64be().row()?;
    let bytes = reader.bytes_u32be().row()?.to_vec();
    reader.finish().row()?;
    if fact_id(&bytes) != id {
        return Err("fact row key does not match fact bytes".to_string());
    }
    Ok(Fact {
        id,
        scope,
        timestamp,
        bytes,
    })
}

/// Rebuild a [`FactScope`] from the three scope columns of a [`FACTS`] row.
fn decode_fact_scope_columns(
    scope: &str,
    scope_kind: &str,
    scope_id: &FactId,
) -> Result<FactScope, String> {
    match scope {
        "global" => {
            if !scope_kind.is_empty() || scope_id != &EMPTY_FACT_ID {
                return Err("global fact scope has scoped columns set".to_string());
            }
            Ok(FactScope::Global)
        }
        "local" => {
            if !scope_kind.is_empty() || scope_id != &EMPTY_FACT_ID {
                return Err("local fact scope has scoped columns set".to_string());
            }
            Ok(FactScope::Local)
        }
        "scoped" => Ok(FactScope::Scoped {
            kind: ScopeKind::new(scope_kind.to_string())?,
            id: *scope_id,
        }),
        other => Err(format!("invalid fact scope {other:?}")),
    }
}

/// Decode a [`CONTEXT_NEEDS`] row.
pub(crate) fn decode_context_need_row(key: &[u8], value: &[u8]) -> Result<ContextNeed, String> {
    expect_empty_value(value, "context need")?;
    let (owner, role, scope, selector) = decode_context_key(key)?;
    Ok(ContextNeed {
        owner,
        role,
        scope,
        selector,
    })
}

/// Decode a [`CONTEXT_OFFERS`] row.
pub(crate) fn decode_context_offer_row(key: &[u8], value: &[u8]) -> Result<ContextOffer, String> {
    expect_empty_value(value, "context offer")?;
    let (owner, role, scope, selector) = decode_context_key(key)?;
    Ok(ContextOffer {
        owner,
        role,
        scope,
        selector,
    })
}

/// Decode the `owner ++ role ++ scope ++ selector` key shared by context need
/// and offer rows (see [`typed_context_key`]).
fn decode_context_key(key: &[u8]) -> Result<(FactId, Role, FactScope, Selector), String> {
    let mut reader = Reader::new(key);
    let owner = reader.array::<32>().row()?;
    let role = Role::new(reader.string_u32be().row()?)?;
    let scope = decode_scope_key(reader.bytes_u32be().row()?)?;
    let selector = Selector::from_bytes(reader.bytes_u32be().row()?.to_vec());
    reader.finish().row()?;
    Ok((owner, role, scope, selector))
}

/// Confirm a key-only row carries no value bytes.
fn expect_empty_value(value: &[u8], what: &str) -> Result<(), String> {
    if value.is_empty() {
        Ok(())
    } else {
        Err(format!("{what} row should have an empty value"))
    }
}

/// Decode a [`PENDING_CONTEXT_CHANGES`] row into the single-entry delta it
/// records.
pub(crate) fn decode_pending_context_change_row(
    key: &[u8],
    value: &[u8],
) -> Result<ContextSetDelta, String> {
    expect_empty_value(value, "pending context change")?;
    let mut reader = Reader::new(key);
    let owner = reader.array::<32>().row()?;
    let change_kind = reader.u64be().row()?;
    let role = Role::new(reader.string_u32be().row()?)?;
    let scope = decode_scope_key(reader.bytes_u32be().row()?)?;
    let selector = Selector::from_bytes(reader.bytes_u32be().row()?.to_vec());
    reader.finish().row()?;

    let mut delta = ContextSetDelta::default();
    match change_kind {
        CONTEXT_CHANGE_NEED => delta.added_needs.push(ContextNeed {
            owner,
            role,
            scope,
            selector,
        }),
        CONTEXT_CHANGE_OFFER => delta.added_offers.push(ContextOffer {
            owner,
            role,
            scope,
            selector,
        }),
        other => return Err(format!("invalid pending context change kind {other}")),
    }
    Ok(delta)
}

/// Decode an [`INTENTS`] row: kind and idempotence key from the key, payload
/// from the value. Durability is determined by the queue table that owns the
/// row.
pub(crate) fn decode_intent_row(key: &[u8], value: &[u8]) -> Result<Intent, String> {
    let mut key_reader = Reader::new(key);
    let kind = IntentKind::new(key_reader.string_u32be().row()?)?;
    let idempotence_key = key_reader.bytes_u32be().row()?.to_vec();
    key_reader.finish().row()?;

    let mut value_reader = Reader::new(value);
    let payload = value_reader.bytes_u32be().row()?.to_vec();
    value_reader.finish().row()?;
    Ok(Intent::new(kind, idempotence_key, payload))
}

// === Scope codec and wire helpers ===

/// Write a [`FactScope`] as a tagged union of bytes.
fn encode_scope(out: &mut Writer, scope: &FactScope) {
    match scope {
        FactScope::Global => out.u8(0),
        FactScope::Local => out.u8(1),
        FactScope::Scoped { kind, id } => {
            out.u8(2);
            out.string_u16be(kind.as_str())
                .expect("scope kind fits u16");
            out.fixed(id);
        }
    }
}

/// Read a [`FactScope`] written by [`encode_scope`].
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

/// Decode a standalone `scope_key` column back into a [`FactScope`].
fn decode_scope_key(bytes: &[u8]) -> Result<FactScope, String> {
    let mut reader = Reader::new(bytes);
    let scope = decode_scope(&mut reader)?;
    reader.finish().row()?;
    Ok(scope)
}

/// Interpret a row key as a 32-byte [`FactId`].
pub(crate) fn decode_fact_id(bytes: &[u8]) -> Result<FactId, String> {
    bytes
        .try_into()
        .map_err(|_| format!("expected 32-byte fact id, got {}", bytes.len()))
}

/// The all-zero [`FactId`] stored in the scope columns of non-scoped facts.
const EMPTY_FACT_ID: FactId = [0u8; 32];

/// Run `write` against a fresh [`Writer`] and return the encoded bytes.
fn encoded_row(write: impl FnOnce(&mut Writer)) -> Vec<u8> {
    let mut out = Writer::new();
    write(&mut out);
    out.finish()
}

/// Write the three scope columns (`tag`, `kind`, `id`) of a [`FACTS`] row.
fn write_fact_scope_columns(out: &mut Writer, scope: &str, kind: &str, id: &FactId) {
    out.string_u32be(scope).expect("scope tag fits u32");
    out.string_u32be(kind).expect("scope kind fits u32");
    out.fixed(id);
}

/// Attach row-decoding context to a [`WireError`].
///
/// Decoders call `.row()` on every `wire` read so a malformed row reports
/// *which layer* failed rather than a bare wire error.
trait RowWireResult<T> {
    fn row(self) -> Result<T, String>;
}

impl<T> RowWireResult<T> for Result<T, WireError> {
    fn row(self) -> Result<T, String> {
        self.map_err(|err| format!("invalid encoded row: {err}"))
    }
}
