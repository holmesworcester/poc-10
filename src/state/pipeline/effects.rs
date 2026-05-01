use crate::db::project_queue::ProjectQueue;
use crate::state::live_hints::{self, LiveHintEvent};
use crate::state::shared_workspace_fanout::fanout_shared_event_enqueue;

use super::drain::drain_project_queue_on_connection;
use super::phases::PersistPhaseOutput;

pub(super) trait PostCommitEffectsExecutor {
    fn run_post_commit_effects(&self, persist_output: &PersistPhaseOutput, batch_size: usize);
}

pub(super) fn run_post_commit_effects<E: PostCommitEffectsExecutor>(
    executor: &E,
    persist_output: &PersistPhaseOutput,
    batch_size: usize,
) {
    executor.run_post_commit_effects(persist_output, batch_size);
}

pub(super) struct SqlitePostCommitEffectsExecutor<'a> {
    db: &'a rusqlite::Connection,
}

impl<'a> SqlitePostCommitEffectsExecutor<'a> {
    pub(super) fn new(db: &'a rusqlite::Connection) -> Self {
        Self { db }
    }
}

impl PostCommitEffectsExecutor for SqlitePostCommitEffectsExecutor<'_> {
    fn run_post_commit_effects(&self, persist_output: &PersistPhaseOutput, batch_size: usize) {
        let pq = ProjectQueue::new(self.db);

        // First drain the origin tenants so removals in this batch are
        // projected before we fan out to siblings.
        let mut tenants: Vec<String> = persist_output.tenants_seen.iter().cloned().collect();
        tenants.sort();

        for tenant_id in &tenants {
            if let Err(e) = drain_project_queue_on_connection(self.db, tenant_id, batch_size) {
                tracing::warn!("project_queue drain error for {}: {}", tenant_id, e);
            }

            if let Ok(h) = pq.health(&tenant_id) {
                if h.pending > 0 || h.max_attempts > 0 {
                    tracing::debug!(
                        tenant = %tenant_id,
                        pending = %h.pending,
                        max_attempts = %h.max_attempts,
                        oldest_age_ms = %h.oldest_age_ms,
                        "project_queue health"
                    );
                }
            }

            match crate::event_modules::post_drain_hooks(self.db, tenant_id) {
                Ok(count) if count > 0 => {
                    tracing::info!(
                        "post-drain hooks: tenant {} resolved {} item(s)",
                        short_id(tenant_id),
                        count
                    );
                }
                Ok(_) => {}
                Err(e) => {
                    tracing::warn!("post-drain hooks failed for {}: {}", short_id(tenant_id), e)
                }
            }
        }

        // Load durably persisted fanout entries (written inside the
        // transaction by persist phase) and process them. This also
        // handles recovery after a crash: any leftover entries from a
        // prior run are picked up here.
        let pending = match crate::state::shared_workspace_fanout::take_pending_fanouts(self.db) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("take_pending_fanouts failed: {}", e);
                Vec::new()
            }
        };
        let mut sibling_tenants = std::collections::HashSet::new();
        let mut sibling_live_hints = Vec::new();
        for fanout in &pending {
            match fanout_shared_event_enqueue(self.db, fanout) {
                Ok(siblings) => {
                    sibling_tenants.extend(siblings.iter().cloned());
                    sibling_live_hints.extend(siblings.into_iter().map(|tenant_id| {
                        LiveHintEvent {
                            tenant_id,
                            event_id: fanout.event_id,
                            source_peer_id: None,
                        }
                    }));
                    // Delete after successful enqueue. The pending entry only
                    // needs to survive the persist→enqueue gap. Once enqueued,
                    // the project_queue handles retry (exponential backoff) for
                    // any sibling-local projection failures (e.g. blocked on
                    // key_secret that arrives later via cascade).
                    let _ = crate::state::shared_workspace_fanout::delete_pending_fanout(
                        self.db, fanout,
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        "same-workspace fanout enqueue failed for {}: {}",
                        short_id(&fanout.origin_peer_id),
                        e
                    );
                }
            }
        }

        live_hints::publish_from_connection(self.db, &sibling_live_hints);

        // Drain newly enqueued sibling project_queue entries.
        let mut sibling_list: Vec<String> = sibling_tenants.into_iter().collect();
        sibling_list.sort();
        for tenant_id in &sibling_list {
            if let Err(e) = drain_project_queue_on_connection(self.db, tenant_id, batch_size) {
                tracing::warn!("sibling project_queue drain error for {}: {}", tenant_id, e);
            }
        }
    }
}

fn short_id(value: &str) -> &str {
    &value[..16.min(value.len())]
}

#[cfg(test)]
mod tests {
    use rusqlite::params;

    use super::*;
    use crate::db::open_in_memory;
    use crate::db::schema::create_tables;

    #[test]
    fn event_pipeline_effects_execute_expected_sqlite_side_effects() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        conn.execute(
            "INSERT INTO project_queue (peer_id, event_id, available_at) VALUES (?1, ?2, 0)",
            params!["tenant-a", "not_base64"],
        )
        .unwrap();

        let persist_output = PersistPhaseOutput {
            persisted_event_ids: vec![[7u8; 32]],
            tenants_seen: std::collections::HashSet::from(["tenant-a".to_string()]),
            live_hints: Vec::new(),
            shared_event_fanouts: Vec::new(),
        };
        let executor = SqlitePostCommitEffectsExecutor::new(&conn);

        run_post_commit_effects(&executor, &persist_output, 16);

        let queue_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM project_queue WHERE peer_id = ?1",
                params!["tenant-a"],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            queue_count, 0,
            "drain command should process and remove queued rows"
        );
    }

    #[test]
    fn event_pipeline_effects_failures_are_best_effort_and_do_not_skip_other_commands() {
        let conn = open_in_memory().unwrap();
        create_tables(&conn).unwrap();

        conn.execute("DROP TABLE project_queue", []).unwrap();

        let persist_output = PersistPhaseOutput {
            persisted_event_ids: vec![[9u8; 32]],
            tenants_seen: std::collections::HashSet::from(["tenant-a".to_string()]),
            live_hints: Vec::new(),
            shared_event_fanouts: Vec::new(),
        };
        let executor = SqlitePostCommitEffectsExecutor::new(&conn);

        run_post_commit_effects(&executor, &persist_output, 8);
    }

    // Wave 1 cleanup: `event_pipeline_effects_fan_out_shared_events_to_same_workspace_siblings_only`
    // was deleted because it relied on multi-tenant-per-workspace fanout
    // (two tenants with separate `recorded_by` rows for the same shared
    // event in the same workspace) — forbidden by the
    // endpoint_workspace_uniqueness invariant. The new model uses
    // workspace_id-keyed projection without per-tenant duplication.
}
