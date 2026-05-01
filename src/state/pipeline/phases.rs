use std::collections::{HashMap, HashSet};

use rusqlite::Connection;

use crate::contracts::event_pipeline_contract::IngestItem;
use crate::crypto::{event_id_to_base64, EventId};
use crate::db::queue::current_timestamp_ms;
use crate::db::store::lookup_workspace_id;
use crate::db::timeline::EventTimeline;
use crate::event_modules::{self as events, registry::EventRegistry, ShareScope};
use crate::state::live_hints::{source_peer_id_from_source_tag, LiveHintEvent};
use crate::state::shared_workspace_fanout::SharedEventFanout;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct PersistPhaseOutput {
    pub persisted_event_ids: Vec<EventId>,
    pub tenants_seen: HashSet<String>,
    pub live_hints: Vec<LiveHintEvent>,
    pub shared_event_fanouts: Vec<SharedEventFanout>,
}

pub(super) fn run_persist_phase(
    db: &Connection,
    batch: &[IngestItem],
    reg: &'static EventRegistry,
    workspace_cache: &mut HashMap<String, String>,
    shared_event_index_stmt: &mut rusqlite::Statement<'_>,
    recorded_stmt: &mut rusqlite::Statement<'_>,
    events_stmt: &mut rusqlite::Statement<'_>,
    enqueue_stmt: &mut rusqlite::Statement<'_>,
) -> PersistPhaseOutput {
    let timeline = EventTimeline::new(db);
    let mut persist_output = PersistPhaseOutput {
        persisted_event_ids: Vec::with_capacity(batch.len()),
        tenants_seen: HashSet::new(),
        live_hints: Vec::new(),
        shared_event_fanouts: Vec::new(),
    };

    for (event_id, blob, recorded_by, source_tag, received_at_ms, first_stored_at_ms) in batch {
        let event_id_b64 = event_id_to_base64(event_id);
        let _ = timeline.mark_received_and_stored_b64(
            &event_id_b64,
            *received_at_ms,
            *first_stored_at_ms,
        );

        if let Some(created_at_ms) = events::extract_created_at_ms(blob) {
            if let Some(type_code) = events::extract_event_type(blob) {
                if let Some(meta) = reg.lookup(type_code) {
                    // Only insert into shared_event_index for shared events (defense-in-depth)
                    if meta.share_scope == ShareScope::Shared {
                        // Look up workspace_id from cache or invites_accepted projection.
                        // For shared workspace events themselves, workspace_id is the
                        // event_id and may exist before invite_accepted projects.
                        let ws_id = if let Some(cached) = workspace_cache.get(recorded_by) {
                            Some(cached.clone())
                        } else if meta.type_name == "workspace" {
                            Some(event_id_b64.clone())
                        } else if let Some(ws) = lookup_workspace_id(db, recorded_by) {
                            workspace_cache.insert(recorded_by.clone(), ws.clone());
                            Some(ws)
                        } else {
                            tracing::warn!(
                                "no accepted workspace binding for {}, skipping shared_event_index for {}",
                                recorded_by,
                                event_id_b64
                            );
                            None
                        };
                        if let Some(ws_id) = ws_id {
                            if let Err(e) = shared_event_index_stmt.execute(rusqlite::params![
                                &ws_id,
                                created_at_ms as i64,
                                event_id.as_slice()
                            ]) {
                                // Non-fatal: shared_event_index is a reconciliation cache;
                                // event will be re-added on next sync session.
                                tracing::warn!(
                                    "shared_event_index insert error for {}: {}",
                                    event_id_b64,
                                    e
                                );
                            }
                        }
                    }

                    if let Err(e) = events_stmt.execute(rusqlite::params![
                        &event_id_b64,
                        meta.type_name,
                        blob.as_slice(),
                        meta.share_scope.as_str(),
                        created_at_ms as i64,
                        current_timestamp_ms()
                    ]) {
                        tracing::warn!("events insert error for {}: {}", event_id_b64, e);
                        continue;
                    }

                    let recorded_at = current_timestamp_ms();
                    let recorded_inserted = match recorded_stmt.execute(rusqlite::params![
                        recorded_by,
                        &event_id_b64,
                        recorded_at,
                        source_tag
                    ]) {
                        Ok(rows) => rows > 0,
                        Err(e) => {
                            tracing::warn!(
                                "recorded_events insert error for {}: {}",
                                event_id_b64,
                                e
                            );
                            continue;
                        }
                    };
                    // Enqueue for durable projection (atomicity boundary 1)
                    let priority_lane = if events::outer_semantic_type_code(blob)
                        == Some(events::EVENT_TYPE_FILE_SLICE)
                    {
                        2
                    } else {
                        1
                    };
                    if let Err(e) = enqueue_stmt.execute(rusqlite::params![
                        recorded_by,
                        &event_id_b64,
                        current_timestamp_ms(),
                        priority_lane,
                        created_at_ms as i64
                    ]) {
                        tracing::warn!("project_queue enqueue error for {}: {}", event_id_b64, e);
                    }

                    persist_output.tenants_seen.insert(recorded_by.clone());
                    persist_output.persisted_event_ids.push(*event_id);
                    if recorded_inserted && meta.share_scope == ShareScope::Shared {
                        persist_output.live_hints.push(LiveHintEvent {
                            tenant_id: recorded_by.clone(),
                            event_id: *event_id,
                            source_peer_id: source_peer_id_from_source_tag(source_tag),
                        });
                    }
                    if meta.share_scope == ShareScope::Shared {
                        if let Some(workspace_id) = if meta.type_name == "workspace" {
                            Some(event_id_b64.clone())
                        } else {
                            lookup_workspace_id(db, recorded_by)
                        } {
                            persist_output.shared_event_fanouts.push(SharedEventFanout {
                                origin_peer_id: recorded_by.clone(),
                                workspace_id,
                                event_id: *event_id,
                            });
                        }
                    }
                } else {
                }
            } else {
            }
        } else {
        }
    }

    // Persist fanout entries durably inside this transaction so they
    // survive a crash between COMMIT and post-commit effects.
    if !persist_output.shared_event_fanouts.is_empty() {
        if let Err(e) = crate::state::shared_workspace_fanout::persist_pending_fanouts(
            db,
            &persist_output.shared_event_fanouts,
        ) {
            tracing::warn!("persist_pending_fanouts error: {}", e);
        }
    }

    persist_output
}

// Wave 1 cleanup: `run_persist_phase_enqueues_encrypted_file_slice_as_bulk`
// was deleted because the file_slice event type has been removed; the persist
// phase no longer demotes encrypted file slices into the bulk lane.
