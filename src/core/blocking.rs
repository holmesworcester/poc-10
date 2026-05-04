use crate::core::store::{EventId, EventStatus, Store};

pub fn missing_dependencies(
    store: &Store,
    dependencies: &[EventId],
) -> rusqlite::Result<Vec<EventId>> {
    let mut dependencies = dependencies.to_vec();
    dependencies.sort();
    dependencies.dedup();

    let mut missing = Vec::new();
    for dependency in dependencies {
        if !store.event_is_applied(&dependency)? {
            missing.push(dependency);
        }
    }
    Ok(missing)
}

pub fn write_blockers(
    store: &Store,
    event_id: &EventId,
    missing: &[EventId],
) -> rusqlite::Result<usize> {
    let mut inserted = 0;
    for dependency in missing {
        inserted += usize::from(store.insert_dependency_wait(dependency, event_id)?);
    }
    Ok(inserted)
}

pub fn unblock_dependents(store: &Store, applied_event_id: &EventId) -> rusqlite::Result<usize> {
    let dependents = store.events_waiting_on(applied_event_id)?;
    store.delete_dependency_waits_for(applied_event_id)?;

    let mut unblocked = 0;
    for dependent in dependents {
        if !store.event_has_dependency_waits(&dependent)?
            && store.set_event_status(&dependent, EventStatus::Blocked, EventStatus::Ready)?
        {
            unblocked += 1;
        }
    }
    Ok(unblocked)
}
