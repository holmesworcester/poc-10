//! Worker-owned lifecycle operations for the generic event store.
//!
//! Protocol rows declares tables and pure row encoders. This module owns the
//! active mechanics that change event lifecycle: idempotent insertion, ready
//! claiming, status transitions, and dependency-edge maintenance. Keeping those
//! verbs here prevents rows modules from becoming hidden workers while still
//! letting the common event pipeline share one audited implementation.
//!
//! The invariant is that lifecycle changes remain generic. This module may move
//! durable event rows between `Ready`, `Blocked`, and `Applied`; it may maintain
//! protocol-wide dependency indexes; it may not decode event families, decide
//! domain deletion policy, write module read models, or enqueue transport.

use crate::core::store::Store;
use crate::legacy::protocol::event_modules::rows;
use crate::legacy::protocol::event_modules::types::{event_id, EventId, EventRecord, EventStatus};

/// Insert a durable event and the generic indexes that make it schedulable.
pub(crate) fn insert_event(
    store: &Store,
    event: &EventRecord,
    status: EventStatus,
) -> rusqlite::Result<bool> {
    let id = event_id(&event.canonical_bytes);
    if store.table_row(rows::EVENTS, &id)?.is_some() {
        return Ok(false);
    }

    let dependencies = unique_dependencies(&event.dependencies);
    let mut rows = vec![rows::event_row(&id, event, status)?];
    if status == EventStatus::Ready {
        rows.push(rows::ready_row(event.timestamp, &id));
    }
    if event.scope.is_shared() {
        rows.push(rows::timestamp_row(
            event.timestamp,
            event.workspace_id,
            &id,
        ));
    }
    for dependency in &dependencies {
        rows.push(rows::edge_row(rows::DEPENDENTS_BY_DEP, dependency, &id));
        rows.push(rows::edge_row(rows::DEPS_BY_DEPENDENT, &id, dependency));
    }
    store.insert_table_rows_in_tx(rows)?;
    Ok(true)
}

/// Return one event's current generic lifecycle status.
pub(crate) fn event_status(
    store: &Store,
    event_id: &EventId,
) -> rusqlite::Result<Option<EventStatus>> {
    rows::read_event(store, event_id).map(|event| event.map(|event| event.status))
}

/// Return whether an event has reached the generic Applied lifecycle state.
pub(crate) fn event_is_applied(store: &Store, event_id: &EventId) -> rusqlite::Result<bool> {
    event_status(store, event_id).map(|status| status == Some(EventStatus::Applied))
}

/// List every retained direct dependent of an event id.
pub(crate) fn direct_dependents(
    store: &Store,
    dependency_id: &EventId,
) -> rusqlite::Result<Vec<EventId>> {
    store
        .table_rows_with_key_prefix(
            rows::DEPENDENTS_BY_DEP,
            dependency_id,
            rows::MAX_DEPENDENCY_ROWS_PER_EVENT,
        )?
        .into_iter()
        .map(|(key, _)| rows::split_edge_key(&key).map(|(_, dependent_id)| dependent_id))
        .collect()
}

/// Record one missing dependency edge in both lookup directions.
pub(crate) fn insert_blocked_event_missing_dep(
    store: &Store,
    missing_dep_id: &EventId,
    blocked_event_id: &EventId,
) -> rusqlite::Result<bool> {
    let primary = rows::edge_row(
        rows::BLOCKED_EVENTS_BY_MISSING_DEP,
        missing_dep_id,
        blocked_event_id,
    );
    let inserted = store.insert_table_rows_in_tx(vec![primary])? > 0;
    store.insert_table_rows_in_tx(vec![rows::edge_row(
        rows::MISSING_DEPS_BY_BLOCKED_EVENT,
        blocked_event_id,
        missing_dep_id,
    )])?;
    Ok(inserted)
}

/// Claim the oldest ready event id without mutating state.
pub(crate) fn next_ready_event(store: &Store) -> rusqlite::Result<Option<EventId>> {
    let mut rows = store.table_rows_with_key_prefix(rows::READY_EVENTS, &[], 1)?;
    let Some((_, value)) = rows.pop() else {
        return Ok(None);
    };
    vec_to_id(value).map(Some)
}

/// Move an event between lifecycle statuses if it is currently in `from`.
pub(crate) fn set_event_status(
    store: &Store,
    event_id: &EventId,
    from: EventStatus,
    to: EventStatus,
) -> rusqlite::Result<bool> {
    let Some(mut event) = rows::read_event(store, event_id)? else {
        return Ok(false);
    };
    if event.status != from {
        return Ok(false);
    }

    let old_ready_key =
        (from == EventStatus::Ready).then(|| rows::ready_key(event.timestamp, event_id));
    event.status = to;
    let mut rows = vec![rows::stored_event_row(event_id, &event)?];
    if to == EventStatus::Ready {
        rows.push(rows::ready_row(event.timestamp, event_id));
    }

    store.replace_table_rows_in_tx(rows)?;
    if let Some(key) = old_ready_key {
        store.delete_table_rows_in_tx(rows::READY_EVENTS, vec![key])?;
    }
    Ok(true)
}

/// Delete every blocker edge waiting on one newly applied dependency.
pub(crate) fn delete_blocked_events_by_missing_dep(
    store: &Store,
    missing_dep_id: &EventId,
) -> rusqlite::Result<usize> {
    let rows = store.table_rows_with_key_prefix(
        rows::BLOCKED_EVENTS_BY_MISSING_DEP,
        missing_dep_id,
        rows::MAX_DEPENDENCY_ROWS_PER_EVENT,
    )?;
    let mut blocked_keys = Vec::with_capacity(rows.len());
    let mut reverse_keys = Vec::with_capacity(rows.len());
    for (key, _) in rows {
        let (missing_dep, blocked_event_id) = rows::split_edge_key(&key)?;
        blocked_keys.push(key);
        reverse_keys.push(rows::edge_key(&blocked_event_id, &missing_dep));
    }
    let deleted =
        store.delete_table_rows_in_tx(rows::BLOCKED_EVENTS_BY_MISSING_DEP, blocked_keys)?;
    store.delete_table_rows_in_tx(rows::MISSING_DEPS_BY_BLOCKED_EVENT, reverse_keys)?;
    Ok(deleted)
}

/// Delete every blocker edge for one event that no longer waits.
pub(crate) fn delete_missing_deps_by_blocked_event(
    store: &Store,
    blocked_event_id: &EventId,
) -> rusqlite::Result<usize> {
    let rows = store.table_rows_with_key_prefix(
        rows::MISSING_DEPS_BY_BLOCKED_EVENT,
        blocked_event_id,
        rows::MAX_DEPENDENCY_ROWS_PER_EVENT,
    )?;
    let mut reverse_keys = Vec::with_capacity(rows.len());
    let mut blocked_keys = Vec::with_capacity(rows.len());
    for (key, _) in rows {
        let (blocked_id, missing_dep) = rows::split_edge_key(&key)?;
        reverse_keys.push(key);
        blocked_keys.push(rows::edge_key(&missing_dep, &blocked_id));
    }
    let deleted =
        store.delete_table_rows_in_tx(rows::MISSING_DEPS_BY_BLOCKED_EVENT, reverse_keys)?;
    store.delete_table_rows_in_tx(rows::BLOCKED_EVENTS_BY_MISSING_DEP, blocked_keys)?;
    Ok(deleted)
}

/// List events currently blocked on a specific missing dependency.
pub(crate) fn blocked_events_by_missing_dep(
    store: &Store,
    missing_dep_id: &EventId,
) -> rusqlite::Result<Vec<EventId>> {
    store
        .table_rows_with_key_prefix(
            rows::BLOCKED_EVENTS_BY_MISSING_DEP,
            missing_dep_id,
            rows::MAX_DEPENDENCY_ROWS_PER_EVENT,
        )?
        .into_iter()
        .map(|(key, _)| rows::split_edge_key(&key).map(|(_, blocked_event_id)| blocked_event_id))
        .collect()
}

/// Return whether a blocked event still has unresolved dependency edges.
pub(crate) fn blocked_event_has_missing_deps(
    store: &Store,
    blocked_event_id: &EventId,
) -> rusqlite::Result<bool> {
    store
        .table_rows_with_key_prefix(rows::MISSING_DEPS_BY_BLOCKED_EVENT, blocked_event_id, 1)
        .map(|rows| !rows.is_empty())
}

fn vec_to_id(bytes: Vec<u8>) -> rusqlite::Result<EventId> {
    bytes.try_into().map_err(|bytes: Vec<u8>| {
        rusqlite::Error::InvalidParameterName(format!(
            "expected 32-byte event id, got {}",
            bytes.len()
        ))
    })
}

fn unique_dependencies(dependencies: &[EventId]) -> Vec<EventId> {
    let mut dependencies = dependencies.to_vec();
    dependencies.sort();
    dependencies.dedup();
    dependencies
}
