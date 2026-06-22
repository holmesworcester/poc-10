//! Recurring sync maintenance.
//!
//! Each runtime turn offers this live-only recurring intent. The builder queues
//! only in daemon-host context when there is sync state to maintain and its
//! process-local maintenance marker says the periodic retry window is due. User
//! commands influence this through projected local state, not by queueing sync
//! work directly.

use crate::core::db::Db;
use crate::core::effects::RuntimeEffects;
use crate::core::intents::{HandlerContext, HandlerResult, Intent, IntentHandler, IntentKind};
use crate::core::runtime::RecurringIntentContext;
use crate::protocol::{connection, sync};
use rusqlite::{params, OptionalExtension};

pub const MAINTAIN_SYNC: &str = "maintain_sync";
const MAINTAIN_SYNC_MARKER: &str = "root_compare";
const MAINTAIN_SYNC_MIN_INTERVAL_MS: u64 = 100;

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

pub fn build_maintain_sync_intent(
    store: &Db,
    context: RecurringIntentContext,
) -> Result<Option<Intent>, String> {
    if context.local_addr.is_none() {
        return Ok(None);
    }
    if !maintenance_due(store, context.now_ms)? {
        return Ok(None);
    }
    if connection::connection::queries::connection_rows(store)?.is_empty() {
        return Ok(None);
    }
    Ok(Some(maintain_sync_intent(context.now_ms)))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MaintainSync {
    run_at_ms: u64,
}

fn maintain_sync_intent(run_at_ms: u64) -> Intent {
    let mut payload = Vec::with_capacity(9);
    payload.push(1);
    payload.extend_from_slice(&run_at_ms.to_be_bytes());
    Intent::new(
        IntentKind::new(MAINTAIN_SYNC).expect("valid maintain_sync kind"),
        maintain_sync_key(run_at_ms),
        payload,
    )
}

fn decode_maintain_sync(intent: &Intent) -> Result<MaintainSync, String> {
    if intent.kind.as_str() != MAINTAIN_SYNC {
        return Err("expected maintain_sync intent".to_string());
    }
    if intent.payload.len() != 9 || intent.payload[0] != 1 {
        return Err("maintain_sync payload is malformed".to_string());
    }
    let run_at_ms = u64::from_be_bytes(intent.payload[1..9].try_into().unwrap());
    if intent.handler_key != maintain_sync_key(run_at_ms) {
        return Err("maintain_sync key does not match payload".to_string());
    }
    Ok(MaintainSync { run_at_ms })
}

fn maintain_sync_key(run_at_ms: u64) -> Vec<u8> {
    let bucket = run_at_ms / MAINTAIN_SYNC_MIN_INTERVAL_MS;
    let mut key = Vec::with_capacity(10);
    key.extend_from_slice(b"v2");
    key.extend_from_slice(&bucket.to_be_bytes());
    key
}

fn maintenance_due(store: &Db, now_ms: u64) -> Result<bool, String> {
    let last = store
        .conn()
        .query_row(
            "SELECT last_run_ms
             FROM sync_maintenance_rows
             WHERE kind = ?1
             LIMIT 1",
            params![MAINTAIN_SYNC_MARKER],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|err| format!("read sync maintenance marker: {err}"))?
        .map(|value| {
            u64::try_from(value)
                .map_err(|_| "sync maintenance marker timestamp is negative".to_string())
        })
        .transpose()?;
    Ok(last.is_none_or(|last| now_ms.saturating_sub(last) >= MAINTAIN_SYNC_MIN_INTERVAL_MS))
}

fn record_maintenance_run(store: &Db, run_at_ms: u64) -> Result<(), String> {
    let run_at_ms = i64::try_from(run_at_ms)
        .map_err(|_| "sync maintenance timestamp exceeds SQLite integer range".to_string())?;
    store
        .conn()
        .execute(
            "INSERT INTO sync_maintenance_rows (kind, last_run_ms)
             VALUES (?1, ?2)
             ON CONFLICT(kind) DO UPDATE SET last_run_ms = excluded.last_run_ms",
            params![MAINTAIN_SYNC_MARKER, run_at_ms],
        )
        .map(|_| ())
        .map_err(|err| format!("record sync maintenance marker: {err}"))
}

#[derive(Debug, Clone, Default)]
pub struct MaintainSyncHandler;

impl MaintainSyncHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for MaintainSyncHandler {
    fn handle(&self, raw: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_maintain_sync(raw)?;
        if context.is_replay() {
            return Ok(RuntimeEffects::new());
        }
        let store = context.db();
        record_maintenance_run(store, input.run_at_ms)?;
        let mut output = RuntimeEffects::new();
        for row in connection::connection::queries::connection_rows(store)? {
            output = sync::seed_connection::append_connection_shareable_facts(
                output,
                store,
                row.connection_id,
            )?;
        }
        Ok(output)
    }
}

// Tests.
// Most-central-first: the positive queue path and retry-window/marker behavior lead, then the skip gates and intent codec.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::db::Db;
    use crate::core::effects::StorageRequirement;
    use crate::core::intents::IntentHandler;
    use crate::core::project_fact::{
        ProjectionContext, ProjectionDispatcher, ProjectionOutput, ProjectionRouteEvidence,
        Projector, RoutedProjection,
    };
    use crate::core::runtime::{HandlerRoute, Runtime, RuntimeDescription};
    use crate::core::schema::CORE_SCHEMA_SOURCE;
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;

    #[test]
    fn recurring_builder_queues_with_connection_in_daemon_host_context() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
            .expect("store");
        seed_connection_row(&store, [8; 32]);

        assert!(build_maintain_sync_intent(&store, daemon_context())
            .expect("build")
            .is_some());
    }

    #[test]
    fn recurring_builder_waits_for_retry_window() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
            .expect("store");
        seed_connection_row(&store, [8; 32]);
        record_maintenance_run(&store, 1_000).expect("record marker");

        assert_eq!(
            build_maintain_sync_intent(
                &store,
                RecurringIntentContext {
                    now_ms: 1_050,
                    local_addr: Some("127.0.0.1:41000".parse().unwrap()),
                }
            )
            .expect("build"),
            None
        );
        assert!(build_maintain_sync_intent(
            &store,
            RecurringIntentContext {
                now_ms: 1_100,
                local_addr: Some("127.0.0.1:41000".parse().unwrap()),
            }
        )
        .expect("build")
        .is_some());
    }

    #[test]
    fn maintenance_marker_write_participates_in_handler_transaction() {
        let mut runtime = Runtime::open_memory(&MAINTAIN_SYNC_RUNTIME).expect("runtime");
        runtime
            .submit_local_intent(maintain_sync_intent(1_000))
            .expect("queue maintenance intent");

        assert!(
            runtime
                .drain_local_intents(1)
                .expect("dispatch maintenance intent"),
            "queued maintenance intent should dispatch"
        );
        assert_eq!(runtime.pending_intent_count(), 0);
        assert!(
            !maintenance_due(runtime.db(), 1_050).expect("read marker"),
            "handler should record its marker inside the dispatch transaction"
        );
    }

    #[test]
    fn recurring_builder_skips_when_no_connections_exist() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
            .expect("store");

        assert_eq!(
            build_maintain_sync_intent(&store, RecurringIntentContext::default()).expect("build"),
            None
        );
    }

    #[test]
    fn recurring_builder_skips_without_daemon_host_context() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
            .expect("store");
        seed_connection_row(&store, [8; 32]);

        assert_eq!(
            build_maintain_sync_intent(&store, RecurringIntentContext::default()).expect("build"),
            None
        );
    }

    #[test]
    fn maintain_sync_intent_round_trips() {
        let intent = maintain_sync_intent(123);

        assert_eq!(
            decode_maintain_sync(&intent).expect("decode"),
            MaintainSync { run_at_ms: 123 }
        );
        assert_eq!(intent.kind.as_str(), MAINTAIN_SYNC);
    }

    fn seed_connection_row(store: &Db, connection_id: crate::core::facts::FactId) {
        let row = connection::connection::connection_row(
            connection::connection::ConnectionRowFields::without_addresses(
                connection_id,
                [1; 32],
                [2; 32],
                [3; 32],
                [4; 32],
                [5; 32],
                [6; 32],
            ),
        )
        .expect("connection row");
        store
            .write_transaction(|tx| tx.insert_values_in_tx(&row).map(|_| ()))
            .expect("insert connection row");
    }

    fn daemon_context() -> RecurringIntentContext {
        RecurringIntentContext {
            now_ms: 123,
            local_addr: Some("127.0.0.1:41000".parse().unwrap()),
        }
    }

    struct NoopProjector;

    impl Projector for NoopProjector {
        fn project(
            &self,
            _fact: &crate::core::facts::Fact,
            _context: &ProjectionContext,
        ) -> Result<ProjectionOutput, String> {
            Ok(ProjectionOutput::new())
        }
    }

    impl ProjectionDispatcher for NoopProjector {
        fn route_evidence(
            &self,
            fact: &crate::core::facts::Fact,
        ) -> Result<ProjectionRouteEvidence, String> {
            Ok(ProjectionRouteEvidence::for_loaded_fact_fixture(fact))
        }

        fn dispatch_projection(
            &self,
            fact: &crate::core::facts::Fact,
            context: &ProjectionContext,
        ) -> Result<RoutedProjection, String> {
            self.project(fact, context)
                .map(|output| RoutedProjection::for_test(fact, output))
        }
    }

    fn noop_projector() -> Box<dyn ProjectionDispatcher> {
        Box::new(NoopProjector)
    }

    fn maintain_sync_handler() -> Box<dyn IntentHandler> {
        Box::new(MaintainSyncHandler::new())
    }

    const MAINTAIN_SYNC_HANDLERS: &[HandlerRoute] = &[HandlerRoute {
        intent_kind: MAINTAIN_SYNC,
        factory: maintain_sync_handler,
        storage_requirement: StorageRequirement::MaintenanceBypass,
        recurrence: None,
    }];

    const MAINTAIN_SYNC_RUNTIME: RuntimeDescription = RuntimeDescription {
        schema_sources: &[FACTS_SCHEMA_SOURCE],
        projected_row_mutation_tables: &[],
        intent_row_mutation_tables: &[],
        projector: noop_projector,
        fact_routes: &[],
        fact_admission: None,
        handlers: MAINTAIN_SYNC_HANDLERS,
    };
}
