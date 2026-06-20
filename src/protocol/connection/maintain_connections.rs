//! Live connection-maintenance loop.
//!
//! `maintain_connections` keeps the local endpoint connected to peers known
//! from retained facts. It is a live-only recurring intent: replay rebuilds the
//! accepted bootstrap peers from `invite_accepted`, then each runtime turn gives
//! this builder a chance to create or retry bounded live connection work. The
//! builder queues only when the host supplied a listener address and its
//! process-local retry marker says the retry window is due; command/query turns
//! still offer the recurring entry, but they cannot create reachable connection
//! attempts.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use crate::core::db::Db;
use crate::core::effects::RuntimeEffects;
use crate::core::intents::{
    HandlerContext, HandlerError, HandlerResult, Intent, IntentHandler, IntentKind, RowMutation,
};
use crate::core::network::{self, NetworkTarget, OutgoingFrame};
use crate::core::runtime::RecurringIntentContext;
use crate::core::wire::{
    Reader as PayloadReader, WireError as PayloadError, Writer as PayloadWriter,
};
use crate::protocol::auth::{endpoint, invite_accepted};
use crate::protocol::connection::connection::queries::answered_request_ids;
use crate::protocol::connection::request::author::{
    create_bootstrap_attempt, CreateBootstrapConnectionAttempt,
};
use crate::protocol::connection::request::queries::{
    bootstrap_connection_attempt_rows, pending_connection_requests, request_by_id,
    BootstrapConnectionAttemptRow,
};
use crate::protocol::connection::request::{self, encode::ADDR_BLOCK_BYTES};
use rusqlite::{params, OptionalExtension};

pub const MAINTAIN_CONNECTIONS: &str = "maintain_connections";
const MAINTAIN_CONNECTIONS_MARKER: &str = "retry";
const MAINTAIN_CONNECTIONS_MIN_INTERVAL_MS: u64 = 100;

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MaintainConnections {
    created_at_ms: u64,
    local_addr: Option<SocketAddr>,
}

/// Build one maintenance tick, or `None` when there is nothing to maintain.
pub fn build_maintain_connections_intent(
    store: &Db,
    context: RecurringIntentContext,
) -> Result<Option<Intent>, String> {
    if context.local_addr.is_none() {
        return Ok(None);
    }
    if !maintenance_due(store, context.now_ms)? {
        return Ok(None);
    }
    if !pending_connection_requests(store)?.is_empty()
        || !bootstrap_peers_needing_attempt(store)?.is_empty()
    {
        return Ok(Some(maintain_connections_intent(MaintainConnections {
            created_at_ms: context.now_ms,
            local_addr: context.local_addr,
        })?));
    }
    Ok(None)
}

fn maintain_connections_intent(input: MaintainConnections) -> Result<Intent, String> {
    let addr = request::encode::encode_optional_addr(input.local_addr)?;
    let mut payload = PayloadWriter::with_capacity(1 + 8 + ADDR_BLOCK_BYTES);
    payload.u8(1);
    payload.u64be(input.created_at_ms);
    payload
        .fixed_slot::<ADDR_BLOCK_BYTES>(&addr)
        .map_err(payload_error)?;
    Ok(Intent::new(
        IntentKind::new(MAINTAIN_CONNECTIONS).expect("valid maintain connections intent kind"),
        maintain_connections_key(&input),
        payload.finish(),
    ))
}

fn decode_maintain_connections(intent: &Intent) -> Result<MaintainConnections, String> {
    if intent.kind.as_str() != MAINTAIN_CONNECTIONS {
        return Err("expected maintain_connections intent".to_string());
    }
    let mut reader = PayloadReader::new(&intent.payload);
    let version = reader.u8().map_err(payload_error)?;
    if version != 1 {
        return Err(format!(
            "unsupported maintain_connections payload {version}"
        ));
    }
    let created_at_ms = reader.u64be().map_err(payload_error)?;
    let addr_block = reader
        .fixed_slot::<ADDR_BLOCK_BYTES>()
        .map_err(payload_error)?;
    reader.finish().map_err(payload_error)?;
    let local_addr = request::project::decode::decode_optional_addr(
        addr_block
            .as_slice()
            .try_into()
            .map_err(|_| "maintain_connections addr block is malformed".to_string())?,
    )?;
    let input = MaintainConnections {
        created_at_ms,
        local_addr,
    };
    if intent.handler_key != maintain_connections_key(&input) {
        return Err("maintain_connections intent key does not match payload".to_string());
    }
    Ok(input)
}

fn maintenance_due(store: &Db, now_ms: u64) -> Result<bool, String> {
    let last = store
        .conn()
        .query_row(
            "SELECT last_run_ms
             FROM connection_maintenance_rows
             WHERE kind = ?1
             LIMIT 1",
            params![MAINTAIN_CONNECTIONS_MARKER],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(|err| format!("read connection maintenance marker: {err}"))?
        .map(|value| {
            u64::try_from(value)
                .map_err(|_| "connection maintenance marker timestamp is negative".to_string())
        })
        .transpose()?;
    Ok(last.is_none_or(|last| now_ms.saturating_sub(last) >= MAINTAIN_CONNECTIONS_MIN_INTERVAL_MS))
}

fn record_maintenance_run(store: &Db, run_at_ms: u64) -> Result<(), String> {
    let run_at_ms = i64::try_from(run_at_ms)
        .map_err(|_| "connection maintenance timestamp exceeds SQLite integer range".to_string())?;
    store
        .conn()
        .execute(
            "INSERT INTO connection_maintenance_rows (kind, last_run_ms)
             VALUES (?1, ?2)
             ON CONFLICT(kind) DO UPDATE SET last_run_ms = excluded.last_run_ms",
            params![MAINTAIN_CONNECTIONS_MARKER, run_at_ms],
        )
        .map(|_| ())
        .map_err(|err| format!("record connection maintenance marker: {err}"))
}

fn maintain_connections_key(input: &MaintainConnections) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:maintain-connections:v2:");
    hash.update(&input.created_at_ms.to_be_bytes());
    hash.update(
        &request::encode::encode_optional_addr(input.local_addr)
            .expect("socket addr encodes for key"),
    );
    hash.finalize().as_bytes().to_vec()
}

#[derive(Debug, Clone, Default)]
pub struct MaintainConnectionsHandler;

impl MaintainConnectionsHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for MaintainConnectionsHandler {
    fn handle(&self, intent: &Intent, context: &HandlerContext) -> HandlerResult {
        if intent.kind.as_str() != MAINTAIN_CONNECTIONS {
            return Err(HandlerError::fatal("expected maintain_connections intent"));
        }
        let input = decode_maintain_connections(intent).map_err(HandlerError::fatal)?;
        if context.is_replay() {
            return Ok(RuntimeEffects::new());
        }
        let store = context.db();
        record_maintenance_run(store, input.created_at_ms).map_err(HandlerError::fatal)?;
        let mut effects = RuntimeEffects::new();

        for pending in pending_connection_requests(store)? {
            network::queue_outgoing_in_tx(
                store,
                NetworkTarget::new(pending.addr),
                OutgoingFrame {
                    bytes: pending.sealed_request_bytes,
                },
            )
            .map_err(|err| {
                HandlerError::fatal(format!("maintain_connections queue outgoing: {err}"))
            })?;
        }

        let Some(local) = endpoint::author::local_endpoint(store)? else {
            return Ok(effects);
        };
        for peer in bootstrap_peers_needing_attempt(store)? {
            let accepted = invite_accepted::fact::InviteAcceptedFact {
                workspace_id: peer.workspace_id,
                invite_fact_id: peer.invite_fact_id,
                bootstrap_hash: peer.bootstrap_hash,
                bootstrap_secret: peer.bootstrap_secret,
                accepted_endpoint_id: peer.accepted_endpoint_id,
                bootstrap_endpoint_id: peer.bootstrap_endpoint_id,
                bootstrap_addr: peer.bootstrap_addr,
                user_authority_fact_id: peer.user_authority_fact_id,
                endpoint_role: peer.endpoint_role,
                identity_scope: peer.identity_scope,
            };
            let attempt = create_bootstrap_attempt(CreateBootstrapConnectionAttempt {
                created_at_ms: input.created_at_ms,
                local_endpoint: local,
                remote_endpoint: peer.bootstrap_endpoint_id,
                invite_secret: invite_accepted::derived_invite_secret(&accepted),
                invite_fact_id: peer.invite_fact_id,
                dialed_addr: peer.bootstrap_addr,
                initiator_addr: input.local_addr,
            })?;
            effects = effects
                .fact(attempt.ephemeral_secret_fact)
                .fact(attempt.request_fact)
                .row_mutation(RowMutation::InsertValues(
                    request::bootstrap_connection_attempt_row(
                        peer.invite_accepted_fact_id,
                        attempt.request_id,
                    )?,
                ));
        }
        Ok(effects)
    }
}

fn bootstrap_peers_needing_attempt(
    store: &Db,
) -> Result<Vec<invite_accepted::queries::InviteAcceptedRow>, String> {
    let Some(local) = endpoint::author::local_endpoint(store)? else {
        return Ok(Vec::new());
    };
    let answered = answered_request_ids(store)?;
    let attempts = bootstrap_connection_attempt_rows(store)?;
    let mut needs = Vec::new();
    for peer in invite_accepted::queries::accepted_bootstrap_peers(store)? {
        if peer.accepted_endpoint_id != local.endpoint
            || peer.bootstrap_endpoint_id == local.endpoint
        {
            continue;
        }
        if attempt_is_active_or_answered(store, &answered, &attempts, peer.invite_accepted_fact_id)?
        {
            continue;
        }
        needs.push(peer);
    }
    Ok(needs)
}

fn attempt_is_active_or_answered(
    store: &Db,
    answered: &BTreeSet<[u8; 32]>,
    attempts: &[BootstrapConnectionAttemptRow],
    invite_accepted_fact_id: [u8; 32],
) -> Result<bool, String> {
    let Some(attempt) = attempts
        .iter()
        .find(|row| row.invite_accepted_fact_id == invite_accepted_fact_id)
    else {
        return Ok(false);
    };
    if answered.contains(&attempt.request_id) {
        return Ok(true);
    }
    Ok(request_by_id(store, &attempt.request_id)?.is_some())
}

fn payload_error(err: PayloadError) -> String {
    format!("invalid maintain_connections payload: {err}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto;
    use crate::core::db::Db;
    use crate::core::effects::StorageRequirement;
    use crate::core::intents::IntentHandler;
    use crate::core::network::{self, NetworkTarget};
    use crate::core::project_fact::{ProjectionContext, ProjectionOutput, Projector};
    use crate::core::runtime::{HandlerRoute, Runtime, RuntimeDescription};
    use crate::core::schema::CORE_SCHEMA_SOURCE;
    use crate::protocol::auth::endpoint::fact::EndpointFact;
    use crate::protocol::auth::endpoint_shared::fact::EndpointRole;
    use crate::protocol::auth::invite_secret::fact::bootstrap_secret_hash;
    use crate::protocol::auth::{endpoint, invite_accepted};
    use crate::protocol::connection::{ephemeral_secret, request};
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;

    #[test]
    fn pending_request_rows_are_queued_directly_to_outgoing_network() {
        let store = Db::open_memory_with_schema_sources(&[
            CORE_SCHEMA_SOURCE,
            network::SCHEMA_SOURCE,
            FACTS_SCHEMA_SOURCE,
        ])
        .expect("store");
        let peer_addr = "127.0.0.1:41000".parse().unwrap();
        let sealed = vec![7; request::encode::SEALED_FACT_BYTES];
        let row =
            request::connection_request_row([1; 32], [2; 32], [3; 32], Some(peer_addr), &sealed)
                .expect("connection request row");
        store
            .write_transaction(|tx| tx.insert_values_in_tx(&row).map(|_| ()))
            .expect("seed pending request row");

        let intent = build_maintain_connections_intent(
            &store,
            RecurringIntentContext {
                now_ms: 123,
                local_addr: Some("127.0.0.1:41001".parse().unwrap()),
            },
        )
        .expect("build")
        .expect("maintenance intent");
        let effects = MaintainConnectionsHandler::new()
            .handle(&intent, &HandlerContext::new(&store))
            .expect("handle");

        assert!(effects.local_intents.is_empty());
        assert_eq!(
            network::claim_outgoing_for_target(&store, NetworkTarget::new(peer_addr), 16)
                .expect("claim queued request")
                .into_iter()
                .map(|row| row.bytes)
                .collect::<Vec<_>>(),
            vec![sealed]
        );
    }

    #[test]
    fn recurring_builder_skips_without_host_listener_address() {
        let store = Db::open_memory_with_schema_sources(&[
            CORE_SCHEMA_SOURCE,
            network::SCHEMA_SOURCE,
            FACTS_SCHEMA_SOURCE,
        ])
        .expect("store");
        let peer_addr = "127.0.0.1:41000".parse().unwrap();
        let sealed = vec![7; request::encode::SEALED_FACT_BYTES];
        let row =
            request::connection_request_row([1; 32], [2; 32], [3; 32], Some(peer_addr), &sealed)
                .expect("connection request row");
        store
            .write_transaction(|tx| tx.insert_values_in_tx(&row).map(|_| ()))
            .expect("seed pending request row");

        let intent = build_maintain_connections_intent(
            &store,
            RecurringIntentContext {
                now_ms: 123,
                local_addr: None,
            },
        )
        .expect("build");

        assert!(intent.is_none());
    }

    #[test]
    fn recurring_builder_waits_for_retry_window() {
        let store = Db::open_memory_with_schema_sources(&[
            CORE_SCHEMA_SOURCE,
            network::SCHEMA_SOURCE,
            FACTS_SCHEMA_SOURCE,
        ])
        .expect("store");
        let peer_addr = "127.0.0.1:41000".parse().unwrap();
        let sealed = vec![7; request::encode::SEALED_FACT_BYTES];
        let row =
            request::connection_request_row([1; 32], [2; 32], [3; 32], Some(peer_addr), &sealed)
                .expect("connection request row");
        store
            .write_transaction(|tx| tx.insert_values_in_tx(&row).map(|_| ()))
            .expect("seed pending request row");
        record_maintenance_run(&store, 1_000).expect("record marker");

        assert_eq!(
            build_maintain_connections_intent(
                &store,
                RecurringIntentContext {
                    now_ms: 1_050,
                    local_addr: Some("127.0.0.1:41001".parse().unwrap()),
                }
            )
            .expect("build"),
            None
        );
        assert!(build_maintain_connections_intent(
            &store,
            RecurringIntentContext {
                now_ms: 1_100,
                local_addr: Some("127.0.0.1:41001".parse().unwrap()),
            }
        )
        .expect("build")
        .is_some());
    }

    #[test]
    fn maintenance_marker_write_participates_in_handler_transaction() {
        let mut runtime = Runtime::open_memory(&MAINTAIN_CONNECTIONS_RUNTIME).expect("runtime");
        let intent = maintain_connections_intent(MaintainConnections {
            created_at_ms: 1_000,
            local_addr: Some("127.0.0.1:41001".parse().unwrap()),
        })
        .expect("maintenance intent");
        runtime
            .submit_local_intent(intent)
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
    fn accepted_invite_row_replays_enough_state_to_create_bootstrap_attempt() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
            .expect("store");
        let local = EndpointFact {
            secret: [2; 32],
            signing_secret: [4; 32],
            endpoint: crypto::x25519_public_key(&[2; 32]),
            signing_public_key: crypto::ed25519_public_key(&[4; 32]),
        };
        let accepted = invite_accepted::fact::InviteAcceptedFact {
            workspace_id: [5; 32],
            invite_fact_id: [6; 32],
            bootstrap_hash: bootstrap_secret_hash(&[7; 32]),
            bootstrap_secret: [7; 32],
            accepted_endpoint_id: local.endpoint,
            bootstrap_endpoint_id: [8; 32],
            bootstrap_addr: "127.0.0.1:41000".parse().unwrap(),
            user_authority_fact_id: None,
            endpoint_role: EndpointRole::Device,
            identity_scope: true,
        };
        let accepted_id = [9; 32];
        store
            .insert_table_values(vec![endpoint::local_endpoint_insert(&local)])
            .expect("seed endpoint rows");
        let accepted_row =
            invite_accepted::invite_accepted_row(accepted_id, &accepted).expect("accepted row");
        store
            .write_transaction(|tx| tx.insert_values_in_tx(&accepted_row).map(|_| ()))
            .expect("seed accepted row");

        let intent = build_maintain_connections_intent(
            &store,
            RecurringIntentContext {
                now_ms: 123,
                local_addr: Some("127.0.0.1:41010".parse().unwrap()),
            },
        )
        .expect("build")
        .expect("maintenance intent");
        let effects = MaintainConnectionsHandler::new()
            .handle(&intent, &HandlerContext::new(&store))
            .expect("handle");

        assert_eq!(effects.facts.len(), 2);
        assert_eq!(
            effects.facts[0].body()[0],
            ephemeral_secret::encode::TYPE_CONNECTION_EPHEMERAL_SECRET
        );
        assert_eq!(
            effects.facts[1].body()[0],
            request::encode::TYPE_CONNECTION_REQUEST
        );
        let ephemeral =
            ephemeral_secret::decode_fact_payload(effects.facts[0].body()).expect("ephemeral");
        let request =
            request::project::decode::open_fact_as_sender(effects.facts[1].body(), &ephemeral)
                .expect("open request");
        assert_eq!(request.from_endpoint, local.endpoint);
        assert_eq!(request.to_endpoint, accepted.bootstrap_endpoint_id);
        assert_eq!(request.dialed_addr, Some(accepted.bootstrap_addr));
        assert_eq!(
            request.initiator_addr,
            Some("127.0.0.1:41010".parse().unwrap())
        );
        assert_eq!(
            request.invite_secret_fact_id,
            invite_accepted::derived_invite_secret_fact_id(&accepted).expect("derived id")
        );
        assert!(effects.row_mutations.iter().any(|mutation| {
            matches!(
                mutation,
                RowMutation::InsertValues(row) if row.table == request::BOOTSTRAP_CONNECTION_ATTEMPT_ROWS
            )
        }));
        assert!(effects.local_intents.is_empty());
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

    fn noop_projector() -> Box<dyn Projector> {
        Box::new(NoopProjector)
    }

    fn maintain_connections_handler() -> Box<dyn IntentHandler> {
        Box::new(MaintainConnectionsHandler::new())
    }

    const MAINTAIN_CONNECTIONS_HANDLERS: &[HandlerRoute] = &[HandlerRoute {
        intent_kind: MAINTAIN_CONNECTIONS,
        factory: maintain_connections_handler,
        storage_requirement: StorageRequirement::MaintenanceBypass,
        recurrence: None,
    }];

    const MAINTAIN_CONNECTIONS_RUNTIME: RuntimeDescription = RuntimeDescription {
        schema_sources: &[network::SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE],
        row_mutation_tables: &[],
        projector: noop_projector,
        fact_routes: &[],
        fact_admission: None,
        handlers: MAINTAIN_CONNECTIONS_HANDLERS,
    };
}
