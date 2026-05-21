use crate::core::context::ContextSetDelta;
use crate::core::context::{ContextNeed, ContextOffer, Role};
use crate::core::matchers::{ContextMatch, ContextMatcher};
use crate::core::pipeline::report::PipelineReport;
use crate::core::pipeline::{persisted_fact, CONTEXT_NEEDS, CONTEXT_OFFERS, PENDING_PROJECTION};
use crate::core::schema_dsl::ColumnType;
use crate::core::store::{ColumnValue, SelectColumn, SelectedRow, SelectedValue, Store};
use std::collections::BTreeSet;

use super::context_store::{
    delete_pending_context_change_in_tx, pending_context_change_batch, scope_key,
    stored_context_matches, PendingContextChange,
};
use super::effects::sqlite_string_error;

/// Drain pending need/offer changes and wake newly matched facts.
pub(super) fn process_context_changes(
    store: &Store,
    matchers: &[&dyn ContextMatcher],
    limit: usize,
) -> Result<PipelineReport, String> {
    let mut report = PipelineReport::default();
    if limit == 0 {
        return Ok(report);
    }

    let changes = pending_context_change_batch(store, limit)?;
    let mut delta = ContextSetDelta::default();
    for change in &changes {
        change.add_to_delta(&mut delta);
    }
    if changes.is_empty() {
        return Ok(report);
    }
    let commit = commit_context_change_matching(store, changes, &delta, matchers)?;
    report.context_matches += commit.context_matches.len();
    report.woken_facts += commit.woken_facts;
    Ok(report)
}

struct ContextChangeCommit {
    context_matches: Vec<ContextMatch>,
    woken_facts: usize,
}

/// Commit one batch of pending context changes.
///
/// Deleting the pending-change rows and inserting dependent pending facts are
/// one transaction, so a crash cannot replay already-consumed changes without
/// also preserving the wakeups they produced.
fn commit_context_change_matching(
    store: &Store,
    pending_changes: Vec<PendingContextChange>,
    delta: &ContextSetDelta,
    matchers: &[&dyn ContextMatcher],
) -> Result<ContextChangeCommit, String> {
    store
        .write_transaction(|tx| {
            for change in &pending_changes {
                delete_pending_context_change_in_tx(tx, change)?;
            }
            let current_delta = current_stored_context_delta(tx, delta)?;
            let mut context_matches = exact_context_matches(tx, &current_delta, matchers)?;
            let custom_matchers = matchers
                .iter()
                .copied()
                .filter(|matcher| matcher.exact_selector_role().is_none())
                .collect::<Vec<_>>();
            context_matches.extend(
                stored_context_matches(tx, &current_delta, &custom_matchers)
                    .map_err(sqlite_string_error)?,
            );
            let context_matches = context_matches.into_iter().collect::<BTreeSet<_>>();
            let mut woken_facts = 0usize;
            for matched in &context_matches {
                if persisted_fact(tx, &matched.need_owner)
                    .map_err(sqlite_string_error)?
                    .is_some()
                    && tx.insert_typed_row_in_tx(
                        PENDING_PROJECTION,
                        &[("owner", ColumnValue::Bytes(&matched.need_owner))],
                    )?
                {
                    woken_facts += 1;
                }
            }
            Ok(ContextChangeCommit {
                context_matches: context_matches.into_iter().collect(),
                woken_facts,
            })
        })
        .map_err(|err| format!("process pending context change: {err}"))
}

fn exact_context_matches(
    store: &Store,
    delta: &ContextSetDelta,
    matchers: &[&dyn ContextMatcher],
) -> rusqlite::Result<Vec<ContextMatch>> {
    let exact_roles = exact_matcher_roles(matchers);
    if exact_roles.is_empty() {
        return Ok(Vec::new());
    }

    let mut matches = BTreeSet::new();
    for need in delta
        .added_needs
        .iter()
        .filter(|need| exact_roles.contains(&need.role))
    {
        for offer_owner in exact_offer_owners_for_need(store, need)? {
            matches.insert(ContextMatch {
                need_owner: need.owner,
                offer_owner,
            });
        }
    }
    for offer in delta
        .added_offers
        .iter()
        .filter(|offer| exact_roles.contains(&offer.role))
    {
        for need_owner in exact_need_owners_for_offer(store, offer)? {
            matches.insert(ContextMatch {
                need_owner,
                offer_owner: offer.owner,
            });
        }
    }
    Ok(matches.into_iter().collect())
}

fn exact_matcher_roles(matchers: &[&dyn ContextMatcher]) -> BTreeSet<Role> {
    matchers
        .iter()
        .filter_map(|matcher| matcher.exact_selector_role().cloned())
        .collect()
}

fn exact_offer_owners_for_need(
    store: &Store,
    need: &ContextNeed,
) -> rusqlite::Result<Vec<[u8; 32]>> {
    let scope_key = scope_key(&need.scope);
    select_owner_ids(
        store,
        r#"
        SELECT owner
        FROM context_offers
        WHERE role = :role
          AND scope_key = :scope_key
          AND selector = :selector
        ORDER BY owner
        "#,
        CONTEXT_OFFERS,
        &[
            (":role", ColumnValue::Text(need.role.as_str())),
            (":scope_key", ColumnValue::Bytes(&scope_key)),
            (":selector", ColumnValue::Bytes(need.selector.as_bytes())),
        ],
        "exact offer owner",
    )
}

fn exact_need_owners_for_offer(
    store: &Store,
    offer: &ContextOffer,
) -> rusqlite::Result<Vec<[u8; 32]>> {
    let scope_key = scope_key(&offer.scope);
    select_owner_ids(
        store,
        r#"
        SELECT n.owner
        FROM context_needs n
        JOIN facts f ON f.id = n.owner
        WHERE n.role = :role
          AND n.scope_key = :scope_key
          AND n.selector = :selector
        ORDER BY f.timestamp, n.owner
        "#,
        CONTEXT_NEEDS,
        &[
            (":role", ColumnValue::Text(offer.role.as_str())),
            (":scope_key", ColumnValue::Bytes(&scope_key)),
            (":selector", ColumnValue::Bytes(offer.selector.as_bytes())),
        ],
        "exact need owner",
    )
}

fn select_owner_ids(
    store: &Store,
    sql: &str,
    table: crate::core::store::TableName,
    params: &[(&str, ColumnValue<'_>)],
    label: &str,
) -> rusqlite::Result<Vec<[u8; 32]>> {
    store
        .select_only(
            sql,
            &[table, crate::core::schema::FACTS],
            params,
            &[SelectColumn {
                name: "owner",
                ty: ColumnType::Bytes { len: Some(32) },
            }],
        )?
        .into_iter()
        .map(|row| selected_owner_id(row, label))
        .collect()
}

fn selected_owner_id(row: SelectedRow, label: &str) -> rusqlite::Result<[u8; 32]> {
    match row.get("owner") {
        Some(SelectedValue::Bytes(bytes)) => bytes.as_slice().try_into().map_err(|_| {
            rusqlite::Error::InvalidParameterName(format!("{label} should be 32 bytes"))
        }),
        _ => Err(rusqlite::Error::InvalidParameterName(format!(
            "{label} query did not return owner"
        ))),
    }
}

/// Keep only added needs/offers that still exist at commit time.
///
/// A fact may have been purged or reprojected after the pending context-change
/// row was written. Matching against current rows prevents stale wakeups.
fn current_stored_context_delta(
    store: &Store,
    delta: &ContextSetDelta,
) -> rusqlite::Result<ContextSetDelta> {
    let mut current = ContextSetDelta::default();
    for need in &delta.added_needs {
        if context_need_exists(store, need)? {
            current.added_needs.push(need.clone());
        }
    }
    for offer in &delta.added_offers {
        if context_offer_exists(store, offer)? {
            current.added_offers.push(offer.clone());
        }
    }
    Ok(current)
}

fn context_need_exists(store: &Store, need: &ContextNeed) -> rusqlite::Result<bool> {
    context_row_exists(
        store,
        CONTEXT_NEEDS,
        r#"
        SELECT owner
        FROM context_needs
        WHERE owner = :owner
          AND role = :role
          AND scope_key = :scope_key
          AND selector = :selector
        LIMIT 1
        "#,
        &need.owner,
        &need.role,
        &scope_key(&need.scope),
        need.selector.as_bytes(),
    )
}

fn context_offer_exists(store: &Store, offer: &ContextOffer) -> rusqlite::Result<bool> {
    context_row_exists(
        store,
        CONTEXT_OFFERS,
        r#"
        SELECT owner
        FROM context_offers
        WHERE owner = :owner
          AND role = :role
          AND scope_key = :scope_key
          AND selector = :selector
        LIMIT 1
        "#,
        &offer.owner,
        &offer.role,
        &scope_key(&offer.scope),
        offer.selector.as_bytes(),
    )
}

fn context_row_exists(
    store: &Store,
    table: crate::core::store::TableName,
    sql: &str,
    owner: &[u8; 32],
    role: &Role,
    scope_key: &[u8],
    selector: &[u8],
) -> rusqlite::Result<bool> {
    Ok(!store
        .select_only(
            sql,
            &[table],
            &[
                (":owner", ColumnValue::Bytes(owner)),
                (":role", ColumnValue::Text(role.as_str())),
                (":scope_key", ColumnValue::Bytes(scope_key)),
                (":selector", ColumnValue::Bytes(selector)),
            ],
            &[SelectColumn {
                name: "owner",
                ty: ColumnType::Bytes { len: Some(32) },
            }],
        )?
        .is_empty())
}
