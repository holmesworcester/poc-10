use crate::core::context::{
    ContextNeed, ContextOffer, ContextSet, ContextSetDelta, Role, Selector,
};
use crate::core::context_change_pipeline::{
    CONTEXT_NEEDS, CONTEXT_OFFERS, FACTS, INTENTS, PENDING_CONTEXT_CHANGES, PENDING_PROJECTION,
    PENDING_TIME_RANGES, TIME_WAKES,
};
use crate::core::facts::{fact_id, Fact, FactId, FactScope, ScopeKind};
use crate::core::intents::{AtomicIntent, Intent, IntentExecution, IntentKind, TableDelete};
use crate::core::matchers::{ContextMatch, ContextMatcher};
use crate::core::projectors::{MatchedContext, ProjectionContext, TimeRange, TimeWake, Timeline};
use crate::core::store::{ColumnValue, Store, TableName, TableRow};
use crate::core::wire::{Reader, WireError, Writer};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) type ExactContextKey = (Role, FactScope, Selector);

pub(crate) fn exact_context_key(
    role: &Role,
    scope: &FactScope,
    selector: &Selector,
) -> ExactContextKey {
    (role.clone(), scope.clone(), selector.clone())
}

pub(crate) fn exact_matcher_roles(matchers: &[&dyn ContextMatcher]) -> BTreeSet<Role> {
    matchers
        .iter()
        .filter_map(|matcher| matcher.exact_selector_role().cloned())
        .collect()
}

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

pub(crate) fn insert_pending_owner_in_tx(store: &Store, owner: FactId) -> rusqlite::Result<usize> {
    store.insert_table_rows_in_tx(vec![TableRow {
        table: PENDING_PROJECTION,
        key: owner.to_vec(),
        value: Vec::new(),
    }])
}

pub(crate) fn purge_fact_in_tx(store: &Store, owner: FactId) -> rusqlite::Result<bool> {
    let mut changed = store.delete_table_rows_in_tx(FACTS, vec![owner.to_vec()])? > 0;

    let need_keys = store
        .table_rows_where(CONTEXT_NEEDS, &[("owner", ColumnValue::Bytes(&owner))])?
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    changed |= !need_keys.is_empty();
    store.delete_table_rows_in_tx(CONTEXT_NEEDS, need_keys)?;

    let offer_keys = store
        .table_rows_where(CONTEXT_OFFERS, &[("owner", ColumnValue::Bytes(&owner))])?
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    changed |= !offer_keys.is_empty();
    store.delete_table_rows_in_tx(CONTEXT_OFFERS, offer_keys)?;

    let time_wake_keys = store
        .table_rows_where(TIME_WAKES, &[("owner", ColumnValue::Bytes(&owner))])?
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    changed |= !time_wake_keys.is_empty();
    store.delete_table_rows_in_tx(TIME_WAKES, time_wake_keys)?;

    let pending_context_change_keys = store
        .table_rows_where(
            PENDING_CONTEXT_CHANGES,
            &[("owner", ColumnValue::Bytes(&owner))],
        )?
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    changed |= !pending_context_change_keys.is_empty();
    store.delete_table_rows_in_tx(PENDING_CONTEXT_CHANGES, pending_context_change_keys)?;

    let pending_time_range_keys = store
        .table_rows_where(
            PENDING_TIME_RANGES,
            &[("owner", ColumnValue::Bytes(&owner))],
        )?
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    changed |= !pending_time_range_keys.is_empty();
    store.delete_table_rows_in_tx(PENDING_TIME_RANGES, pending_time_range_keys)?;

    changed |= store.delete_table_rows_in_tx(PENDING_PROJECTION, vec![owner.to_vec()])? > 0;
    Ok(changed)
}

pub(crate) fn record_intent_in_tx(store: &Store, intent: &Intent) -> rusqlite::Result<bool> {
    store
        .insert_table_rows_in_tx(vec![intent_row(intent)])
        .map(|count| count > 0)
}

pub(crate) fn fact_row(fact: &Fact) -> TableRow {
    TableRow {
        table: FACTS,
        key: fact.id.to_vec(),
        value: typed_fact_value(fact),
    }
}

pub(crate) fn context_need_row(need: &ContextNeed) -> TableRow {
    TableRow {
        table: CONTEXT_NEEDS,
        key: typed_context_need_key(need),
        value: Vec::new(),
    }
}

pub(crate) fn context_offer_row(offer: &ContextOffer) -> TableRow {
    TableRow {
        table: CONTEXT_OFFERS,
        key: typed_context_offer_key(offer),
        value: Vec::new(),
    }
}

pub(crate) fn time_wake_row(wake: &TimeWake) -> TableRow {
    TableRow {
        table: TIME_WAKES,
        key: typed_time_wake_key(wake),
        value: Vec::new(),
    }
}

pub(crate) fn pending_time_range_row(owner: FactId, range: &TimeRange) -> TableRow {
    TableRow {
        table: PENDING_TIME_RANGES,
        key: typed_pending_time_range_key(owner, range),
        value: Vec::new(),
    }
}

pub(crate) fn intent_row(intent: &Intent) -> TableRow {
    TableRow {
        table: INTENTS,
        key: intent_row_key(intent),
        value: typed_intent_value(intent),
    }
}

pub(crate) fn validate_atomic_row_intents(
    intents: &[Intent],
    allowed_tables: &[TableName],
) -> Result<(), String> {
    for intent in intents {
        if intent.execution == IntentExecution::Atomic {
            AtomicIntent::from_intent(intent, allowed_tables)?;
        }
    }
    Ok(())
}

pub(crate) fn atomic_row_mutations(
    intents: &[Intent],
    allowed_tables: &[TableName],
) -> Result<(Vec<TableRow>, Vec<TableDelete>), String> {
    let mut rows = Vec::new();
    let mut deletes = Vec::<TableDelete>::new();
    for intent in intents {
        if intent.execution != IntentExecution::Atomic {
            continue;
        }
        match AtomicIntent::from_intent(intent, allowed_tables)? {
            AtomicIntent::PutRow(row) => rows.push(row),
            AtomicIntent::DeleteRow(delete) => deletes.push(delete),
        }
    }
    Ok((rows, deletes))
}

pub(crate) fn sqlite_string_error(err: String) -> rusqlite::Error {
    rusqlite::Error::InvalidParameterName(err)
}

pub(crate) fn pending_context_change_rows(delta: &ContextSetDelta) -> Vec<TableRow> {
    delta
        .added_needs
        .iter()
        .map(pending_context_need_row)
        .chain(delta.added_offers.iter().map(pending_context_offer_row))
        .collect()
}

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

pub(crate) fn stored_pending_time_ranges_for_owner(
    store: &Store,
    owner: &FactId,
) -> Result<Vec<TimeRange>, String> {
    store
        .table_rows_where(PENDING_TIME_RANGES, &[("owner", ColumnValue::Bytes(owner))])
        .map_err(|err| format!("load pending time ranges: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_pending_time_range_row(&key, &value))
        .collect()
}

pub(crate) fn delete_pending_time_ranges_for_owner_in_tx(
    store: &Store,
    owner: FactId,
) -> rusqlite::Result<()> {
    let keys = store
        .table_rows_where(
            PENDING_TIME_RANGES,
            &[("owner", ColumnValue::Bytes(&owner))],
        )?
        .into_iter()
        .map(|(key, _)| key)
        .collect::<Vec<_>>();
    store.delete_table_rows_in_tx(PENDING_TIME_RANGES, keys)?;
    Ok(())
}

pub(crate) fn stored_context_matches(
    store: &Store,
    delta: &ContextSetDelta,
    matchers: &[&dyn ContextMatcher],
) -> Result<Vec<ContextMatch>, String> {
    let mut matches = BTreeSet::new();
    let exact_roles = exact_matcher_roles(matchers);
    if !exact_roles.is_empty() {
        let added_exact_needs = delta
            .added_needs
            .iter()
            .filter(|need| exact_roles.contains(&need.role))
            .collect::<Vec<_>>();
        let added_exact_offers = delta
            .added_offers
            .iter()
            .filter(|offer| exact_roles.contains(&offer.role))
            .collect::<Vec<_>>();
        let offers_by_key =
            stored_exact_offers_for_needs(store, added_exact_needs.iter().copied())?;
        let needs_by_key =
            stored_exact_needs_for_offers(store, added_exact_offers.iter().copied())?;
        for need in delta
            .added_needs
            .iter()
            .filter(|need| exact_roles.contains(&need.role))
        {
            let key = exact_context_key(&need.role, &need.scope, &need.selector);
            for offer in offers_by_key.get(&key).into_iter().flatten() {
                matches.insert(ContextMatch {
                    need_owner: need.owner,
                    offer_owner: offer.owner,
                });
            }
        }
        for offer in delta
            .added_offers
            .iter()
            .filter(|offer| exact_roles.contains(&offer.role))
        {
            let key = exact_context_key(&offer.role, &offer.scope, &offer.selector);
            for need in needs_by_key.get(&key).into_iter().flatten() {
                matches.insert(ContextMatch {
                    need_owner: need.owner,
                    offer_owner: offer.owner,
                });
            }
        }
    }

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

fn stored_needs_for_owner(store: &Store, owner: &FactId) -> Result<Vec<ContextNeed>, String> {
    load_context_needs_from_rows(
        store
            .table_rows_where(CONTEXT_NEEDS, &[("owner", ColumnValue::Bytes(owner))])
            .map_err(|err| format!("load context needs: {err}"))?,
    )
}

fn stored_offers_for_owner(store: &Store, owner: &FactId) -> Result<Vec<ContextOffer>, String> {
    load_context_offers_from_rows(
        store
            .table_rows_where(CONTEXT_OFFERS, &[("owner", ColumnValue::Bytes(owner))])
            .map_err(|err| format!("load context offers: {err}"))?,
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

fn stored_exact_needs_for_offers<'a>(
    store: &Store,
    offers: impl Iterator<Item = &'a ContextOffer>,
) -> Result<BTreeMap<ExactContextKey, Vec<ContextNeed>>, String> {
    let mut groups = BTreeMap::<(Role, Vec<u8>), BTreeSet<Vec<u8>>>::new();
    for offer in offers {
        groups
            .entry((offer.role.clone(), scope_key(&offer.scope)))
            .or_default()
            .insert(offer.selector.as_bytes().to_vec());
    }

    let mut out = BTreeMap::<ExactContextKey, Vec<ContextNeed>>::new();
    for ((role, scope_key), selectors) in groups {
        let selector_values = selectors
            .iter()
            .map(|selector| ColumnValue::Bytes(selector.as_slice()))
            .collect::<Vec<_>>();
        for need in load_context_needs_from_rows(
            store
                .table_rows_where_in(
                    CONTEXT_NEEDS,
                    &[
                        ("role", ColumnValue::Text(role.as_str())),
                        ("scope_key", ColumnValue::Bytes(&scope_key)),
                    ],
                    "selector",
                    &selector_values,
                )
                .map_err(|err| format!("load exact context needs: {err}"))?,
        )? {
            out.entry(exact_context_key(&need.role, &need.scope, &need.selector))
                .or_default()
                .push(need);
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

fn load_context_needs_from_rows(rows: Vec<(Vec<u8>, Vec<u8>)>) -> Result<Vec<ContextNeed>, String> {
    rows.into_iter()
        .map(|(key, value)| decode_context_need_row(&key, &value))
        .collect()
}

fn load_context_offers_from_rows(
    rows: Vec<(Vec<u8>, Vec<u8>)>,
) -> Result<Vec<ContextOffer>, String> {
    rows.into_iter()
        .map(|(key, value)| decode_context_offer_row(&key, &value))
        .collect()
}

fn typed_context_need_key(need: &ContextNeed) -> Vec<u8> {
    encoded_row(|key| {
        key.fixed(&need.owner);
        key.string_u32be(need.role.as_str())
            .expect("context role fits u32");
        key.bytes_u32be(&scope_key(&need.scope))
            .expect("scope key fits u32");
        key.bytes_u32be(need.selector.as_bytes())
            .expect("selector fits u32");
    })
}

fn typed_context_offer_key(offer: &ContextOffer) -> Vec<u8> {
    encoded_row(|key| {
        key.fixed(&offer.owner);
        key.string_u32be(offer.role.as_str())
            .expect("context role fits u32");
        key.bytes_u32be(&scope_key(&offer.scope))
            .expect("scope key fits u32");
        key.bytes_u32be(offer.selector.as_bytes())
            .expect("selector fits u32");
    })
}

fn typed_time_wake_key(wake: &TimeWake) -> Vec<u8> {
    encoded_row(|key| {
        key.string_u32be(wake.timeline.as_str())
            .expect("timeline fits u32");
        key.u64be(wake.at);
        key.fixed(&wake.owner);
    })
}

fn typed_pending_time_range_key(owner: FactId, range: &TimeRange) -> Vec<u8> {
    encoded_row(|key| {
        key.fixed(&owner);
        key.string_u32be(range.timeline.as_str())
            .expect("timeline fits u32");
        key.bool8(range.start_exclusive.is_some());
        key.u64be(range.start_exclusive.unwrap_or(0));
        key.u64be(range.end_inclusive);
    })
}

fn pending_context_need_row(need: &ContextNeed) -> TableRow {
    let key = encoded_row(|key| {
        key.fixed(&need.owner);
        key.u64be(0);
        key.string_u32be(need.role.as_str())
            .expect("context role fits u32");
        key.bytes_u32be(&scope_key(&need.scope))
            .expect("scope key fits u32");
        key.bytes_u32be(need.selector.as_bytes())
            .expect("selector fits u32");
    });
    TableRow {
        table: PENDING_CONTEXT_CHANGES,
        key,
        value: Vec::new(),
    }
}

fn pending_context_offer_row(offer: &ContextOffer) -> TableRow {
    let key = encoded_row(|key| {
        key.fixed(&offer.owner);
        key.u64be(1);
        key.string_u32be(offer.role.as_str())
            .expect("context role fits u32");
        key.bytes_u32be(&scope_key(&offer.scope))
            .expect("scope key fits u32");
        key.bytes_u32be(offer.selector.as_bytes())
            .expect("selector fits u32");
    });
    TableRow {
        table: PENDING_CONTEXT_CHANGES,
        key,
        value: Vec::new(),
    }
}

pub(crate) fn scope_key(scope: &FactScope) -> Vec<u8> {
    let mut out = Writer::new();
    encode_scope(&mut out, scope);
    out.finish()
}

pub(crate) fn intent_row_key(intent: &Intent) -> Vec<u8> {
    encoded_row(|key| {
        key.string_u32be(intent.kind.as_str())
            .expect("intent kind fits u32");
        key.bytes_u32be(&intent.key)
            .expect("intent idempotence key fits u32");
    })
}

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

pub fn persisted_fact(store: &Store, id: &FactId) -> Result<Option<Fact>, String> {
    store
        .table_row(FACTS, id)
        .map_err(|err| format!("load fact row: {err}"))?
        .map(|value| decode_fact_row(id, &value))
        .transpose()
}

pub fn persisted_facts(store: &Store) -> Result<Vec<Fact>, String> {
    store
        .table_rows(FACTS)
        .map_err(|err| format!("load fact rows: {err}"))?
        .into_iter()
        .map(|(key, value)| decode_fact_row(&key, &value))
        .collect()
}

pub fn persisted_context(store: &Store, owner: &FactId) -> Result<Option<ContextSet>, String> {
    let context = stored_context_for_owner(store, owner)?;
    if context.needs.is_empty() && context.offers.is_empty() {
        Ok(None)
    } else {
        Ok(Some(context))
    }
}

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

pub(crate) fn decode_context_need_row(key: &[u8], value: &[u8]) -> Result<ContextNeed, String> {
    if !value.is_empty() {
        return Err("typed context need row should not have value bytes".to_string());
    }
    let mut reader = Reader::new(key);
    let owner = reader.array::<32>().row()?;
    let role = Role::new(reader.string_u32be().row()?)?;
    let scope = decode_scope_key(reader.bytes_u32be().row()?)?;
    let selector = Selector::from_bytes(reader.bytes_u32be().row()?.to_vec());
    reader.finish().row()?;
    Ok(ContextNeed {
        owner,
        role,
        scope,
        selector,
    })
}

pub(crate) fn decode_context_offer_row(key: &[u8], value: &[u8]) -> Result<ContextOffer, String> {
    if !value.is_empty() {
        return Err("typed context offer row should not have value bytes".to_string());
    }
    let mut reader = Reader::new(key);
    let owner = reader.array::<32>().row()?;
    let role = Role::new(reader.string_u32be().row()?)?;
    let scope = decode_scope_key(reader.bytes_u32be().row()?)?;
    let selector = Selector::from_bytes(reader.bytes_u32be().row()?.to_vec());
    reader.finish().row()?;
    Ok(ContextOffer {
        owner,
        role,
        scope,
        selector,
    })
}

pub(crate) fn decode_pending_context_change_row(
    key: &[u8],
    value: &[u8],
) -> Result<ContextSetDelta, String> {
    if !value.is_empty() {
        return Err("pending context change row value must be empty".to_string());
    }
    let mut reader = Reader::new(key);
    let owner = reader.array::<32>().row()?;
    let change_kind = reader.u64be().row()?;
    let role = Role::new(reader.string_u32be().row()?)?;
    let scope = decode_scope_key(reader.bytes_u32be().row()?)?;
    let selector = Selector::from_bytes(reader.bytes_u32be().row()?.to_vec());
    reader.finish().row()?;

    let mut delta = ContextSetDelta::default();
    match change_kind {
        0 => delta.added_needs.push(ContextNeed {
            owner,
            role,
            scope,
            selector,
        }),
        1 => delta.added_offers.push(ContextOffer {
            owner,
            role,
            scope,
            selector,
        }),
        other => return Err(format!("invalid pending context change kind {other}")),
    }
    Ok(delta)
}

pub(crate) fn decode_time_wake_row(key: &[u8], value: &[u8]) -> Result<TimeWake, String> {
    if !value.is_empty() {
        return Err("time wake row value must be empty".to_string());
    }
    let mut reader = Reader::new(key);
    let timeline = Timeline::new(reader.string_u32be().row()?)?;
    let at = reader.u64be().row()?;
    let owner = reader.array::<32>().row()?;
    reader.finish().row()?;
    Ok(TimeWake {
        owner,
        timeline,
        at,
    })
}

fn decode_pending_time_range_row(key: &[u8], value: &[u8]) -> Result<TimeRange, String> {
    if !value.is_empty() {
        return Err("pending time range row value must be empty".to_string());
    }
    let mut reader = Reader::new(key);
    let _owner = reader.array::<32>().row()?;
    let timeline = Timeline::new(reader.string_u32be().row()?)?;
    let has_start = reader.bool8().row()?;
    let start = reader.u64be().row()?;
    let end_inclusive = reader.u64be().row()?;
    reader.finish().row()?;
    Ok(TimeRange {
        timeline,
        start_exclusive: has_start.then_some(start),
        end_inclusive,
    })
}

fn typed_intent_value(intent: &Intent) -> Vec<u8> {
    encoded_row(|out| {
        out.u64be(intent_execution_code(intent.execution));
        out.bytes_u32be(&intent.payload)
            .expect("intent payload fits u32");
    })
}

fn intent_execution_code(execution: IntentExecution) -> u64 {
    match execution {
        IntentExecution::Atomic => 0,
        IntentExecution::Deferred => 1,
        IntentExecution::Ephemeral => 2,
    }
}

pub(crate) fn decode_intent_row(key: &[u8], value: &[u8]) -> Result<Intent, String> {
    let mut key_reader = Reader::new(key);
    let kind = IntentKind::new(key_reader.string_u32be().row()?)?;
    let idempotence_key = key_reader.bytes_u32be().row()?.to_vec();
    key_reader.finish().row()?;

    let mut value_reader = Reader::new(value);
    let execution = match value_reader.u64be().row()? {
        0 => IntentExecution::Atomic,
        1 => IntentExecution::Deferred,
        2 => IntentExecution::Ephemeral,
        other => return Err(format!("invalid intent execution tag {other}")),
    };
    let payload = value_reader.bytes_u32be().row()?.to_vec();
    value_reader.finish().row()?;
    Ok(Intent::new(kind, execution, idempotence_key, payload))
}

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

fn decode_scope_key(bytes: &[u8]) -> Result<FactScope, String> {
    let mut reader = Reader::new(bytes);
    let scope = decode_scope(&mut reader)?;
    reader.finish().row()?;
    Ok(scope)
}

pub(crate) fn decode_fact_id(bytes: &[u8]) -> Result<FactId, String> {
    bytes
        .try_into()
        .map_err(|_| format!("expected 32-byte fact id, got {}", bytes.len()))
}

const EMPTY_FACT_ID: FactId = [0u8; 32];

fn encoded_row(write: impl FnOnce(&mut Writer)) -> Vec<u8> {
    let mut out = Writer::new();
    write(&mut out);
    out.finish()
}

fn write_fact_scope_columns(out: &mut Writer, scope: &str, kind: &str, id: &FactId) {
    out.string_u32be(scope).expect("scope tag fits u32");
    out.string_u32be(kind).expect("scope kind fits u32");
    out.fixed(id);
}

trait RowWireResult<T> {
    fn row(self) -> Result<T, String>;
}

impl<T> RowWireResult<T> for Result<T, WireError> {
    fn row(self) -> Result<T, String> {
        self.map_err(|err| format!("invalid encoded row: {err}"))
    }
}
