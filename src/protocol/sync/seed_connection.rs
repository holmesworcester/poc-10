//! Bounded sync seeding for one connection.
//!
//! Projection emits this intent when a connection row becomes durable. The
//! handler reads the connection-scoped shareable-fact index, sends one root
//! negentropy compare for the initial round, and coalesces newly shareable
//! facts into timestamp-bucket tail sends.

use crate::core::effects::RuntimeEffects;
use crate::core::{
    db::Db,
    facts::{Fact, FactId},
    intents::{HandlerContext, HandlerError, HandlerResult, Intent, IntentHandler, IntentKind},
};
use crate::protocol::connection::send_facts_on_connection::{
    send_facts_on_connection_intent, SendFactsOnConnection,
};
use crate::protocol::{connection, sync};
use std::collections::BTreeSet;

pub const SEED_CONNECTION_SYNC: &str = "seed_connection_sync";

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedConnectionSync {
    pub connection_id: FactId,
}

pub fn seed_connection_sync_intent(input: SeedConnectionSync) -> Intent {
    Intent::new(
        IntentKind::new(SEED_CONNECTION_SYNC).expect("valid seed_connection_sync kind"),
        seed_connection_sync_key(input.connection_id),
        encode_seed_connection_sync(&input),
    )
}

pub fn decode_seed_connection_sync(intent: &Intent) -> Result<SeedConnectionSync, String> {
    if intent.kind.as_str() != SEED_CONNECTION_SYNC {
        return Err("expected seed_connection_sync intent".into());
    }
    if intent.payload.len() != 33 || intent.payload[0] != 1 {
        return Err("invalid seed_connection_sync payload".into());
    }
    let input = SeedConnectionSync {
        connection_id: intent.payload[1..33].try_into().unwrap(),
    };
    if intent.handler_key != seed_connection_sync_key(input.connection_id) {
        return Err("seed_connection_sync key does not match payload".into());
    }
    Ok(input)
}

fn seed_connection_sync_key(connection_id: FactId) -> Vec<u8> {
    let mut key = Vec::with_capacity(32);
    key.extend_from_slice(&connection_id);
    key
}

fn encode_seed_connection_sync(input: &SeedConnectionSync) -> Vec<u8> {
    let mut payload = Vec::with_capacity(33);
    payload.push(1);
    payload.extend_from_slice(&input.connection_id);
    payload
}

#[derive(Debug, Clone, Default)]
pub struct SeedConnectionSyncHandler;

impl SeedConnectionSyncHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for SeedConnectionSyncHandler {
    fn handle(&self, raw: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_seed_connection_sync(raw)?;
        if context.is_replay() {
            return Ok(RuntimeEffects::new());
        }
        let store = context.db();
        let Some(_) =
            connection::connection::queries::connection_by_id(store, &input.connection_id)
                .map_err(|err| {
                    HandlerError::fatal(format!("seed_connection_sync connection row: {err}"))
                })?
        else {
            return Ok(RuntimeEffects::new());
        };
        advertise_connection_shareable_facts(store, input.connection_id)
    }
}

pub fn advertise_connection_shareable_facts(store: &Db, connection_id: FactId) -> HandlerResult {
    append_connection_shareable_facts(RuntimeEffects::new(), store, connection_id)
}

pub fn append_connection_shareable_facts(
    output: RuntimeEffects,
    store: &Db,
    connection_id: FactId,
) -> HandlerResult {
    let range = sync::local_setting::active_range(store)?;
    let summary = sync::shared_fact::range_summary_for_connection(store, connection_id, range)?;
    let compare = sync::compare::author::start_compare_fact_for_range_with_summary(
        connection_id,
        range,
        summary,
    )?;
    Ok(output
        .fact(compare.clone())
        .intent(send_facts_on_connection_intent(SendFactsOnConnection {
            connection_id,
            fact_ids: vec![compare.id],
        })))
}

pub fn advertise_indexed_fact_to_connections(store: &Db, fact: &Fact) -> HandlerResult {
    advertise_indexed_fact_to_connections_except(store, fact, &BTreeSet::new())
}

pub fn advertise_indexed_fact_to_connections_except(
    store: &Db,
    fact: &Fact,
    excluded_connection_ids: &BTreeSet<FactId>,
) -> HandlerResult {
    let mut output = RuntimeEffects::new();
    for connection_id in sync::shared_fact::connection_ids_for_shareable_fact(store, fact)? {
        if excluded_connection_ids.contains(&connection_id) {
            continue;
        }
        output = append_live_tail_send(output, store, connection_id, fact)?;
    }
    Ok(output)
}

fn append_live_tail_send(
    output: RuntimeEffects,
    store: &Db,
    connection_id: FactId,
    fact: &Fact,
) -> HandlerResult {
    let active_range = sync::local_setting::active_range(store)?;
    if !sync::local_setting::contains_timestamp(active_range, fact.timestamp) {
        return Ok(output);
    }
    let fact_ids = sync::shared_fact::expand_fact_ids_with_context_for_connection(
        store,
        connection_id,
        &[fact.id],
    )?;
    Ok(
        output.intent(send_facts_on_connection_intent(SendFactsOnConnection {
            connection_id,
            fact_ids,
        })),
    )
}

// Tests.
// Most-central-first: the root-compare advertise and handler happy paths lead, then range/live-tail behavior, then gates and the intent codec.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto;
    use crate::core::db::Db;
    use crate::core::facts::{FactScope, ScopeKind};
    use crate::core::project_fact::ProjectedRowMutation;
    use crate::core::project_fact::{ProjectionContext, Projector};
    use crate::core::schema::CORE_SCHEMA_SOURCE;
    use crate::protocol::auth::endpoint::{self as endpoint_rows, fact::EndpointFact};
    use crate::protocol::auth::endpoint_shared::{
        self as endpoint_shared_rows,
        fact::{EndpointDeviceName, EndpointRole, EndpointSharedFact},
    };
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;
    use crate::protocol::sync::share_fact_with_sync::{ShareFactWithSync, SyncShareState};
    use crate::protocol::sync::shared_fact;

    #[test]
    fn advertise_connection_shareable_facts_emits_root_compare_and_send_intent() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
            .expect("store");
        let workspace_id = [9; 32];
        let connection_id = [8; 32];
        let fact = Fact::new(
            FactScope::Scoped {
                kind: ScopeKind::new("workspace").unwrap(),
                id: workspace_id,
            },
            42,
            vec![1, 2, 3],
        );
        let connection_row = connection::connection::connection_row(
            connection::connection::ConnectionRowFields::without_addresses(
                connection_id,
                [1; 32],
                [2; 32],
                [3; 32],
                [7; 32],
                [8; 32],
                [9; 32],
            ),
        )
        .expect("connection row");
        let shareable_row = shared_fact::shareable_fact_row(shared_fact::ShareableFactRow {
            workspace_id,
            fact_id: fact.id,
            timestamp_ms: fact.timestamp,
        });
        store
            .write_transaction(|tx| {
                tx.insert_values_in_tx(&connection_row)?;
                tx.insert_values_in_tx(&shareable_row)?;
                Ok(())
            })
            .expect("insert rows");

        let output = advertise_connection_shareable_facts(&store, connection_id).expect("seed");

        assert_eq!(output.facts.len(), 1);
        let compare = sync::compare::project::decode::decode_fact(&output.facts[0].bytes)
            .expect("compare fact");
        assert_eq!(compare.connection_id, connection_id);
        assert_eq!(compare.range, sync::compare::fact::TimestampRange::ROOT);
        assert!(compare.response_requested);
        assert_eq!(output.intents.len(), 1);
    }

    #[test]
    fn seed_connection_sync_handler_depends_on_connection_row_not_response_fact() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
            .expect("store");
        let connection_id = [8; 32];
        let row = connection::connection::connection_row(
            connection::connection::ConnectionRowFields::without_addresses(
                connection_id,
                [1; 32],
                [2; 32],
                [3; 32],
                [7; 32],
                [8; 32],
                [9; 32],
            ),
        )
        .expect("connection row");
        store
            .write_transaction(|tx| tx.insert_values_in_tx(&row).map(|_| ()))
            .expect("insert row");
        let intent = seed_connection_sync_intent(SeedConnectionSync { connection_id });
        let handler = SeedConnectionSyncHandler::new();

        assert!(intent.context_fact_ids.is_empty());
        let output = handler
            .handle(&intent, &HandlerContext::new(&store))
            .expect("handle seed");

        assert_eq!(output.facts.len(), 1);
        assert_eq!(output.intents.len(), 1);
    }

    #[test]
    fn live_tail_send_expands_projector_context_for_trigger_fact() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
            .expect("store");
        let workspace_id = [9; 32];
        let connection_id = [8; 32];
        let local_secret = [11; 32];
        let local_endpoint = crypto::x25519_public_key(&local_secret);
        let remote_endpoint = [2; 32];
        let context_fact = Fact::new(workspace_scope(workspace_id), 10, vec![99, 1]);
        let owner_fact = Fact::new(workspace_scope(workspace_id), 20, vec![99, 2]);

        store
            .write_transaction(|tx| {
                crate::core::project_fact::insert_fact_and_pending_in_tx(tx, &context_fact)?;
                crate::core::project_fact::insert_fact_and_pending_in_tx(tx, &owner_fact)?;
                Ok(())
            })
            .expect("persist facts");
        let row = endpoint_rows::local_endpoint_insert(&EndpointFact {
            endpoint: local_endpoint,
            secret: local_secret,
            signing_public_key: crypto::ed25519_public_key(&[13; 32]),
            signing_secret: [13; 32],
        });
        store
            .insert_table_values(vec![row])
            .expect("seed endpoint row");
        let connection_row = connection::connection::connection_row(
            connection::connection::ConnectionRowFields::without_addresses(
                connection_id,
                local_endpoint,
                remote_endpoint,
                [3; 32],
                [7; 32],
                [8; 32],
                [9; 32],
            ),
        )
        .expect("connection row");
        let endpoint_shared_row = endpoint_shared_rows::endpoint_shared_row(
            [5; 32],
            &EndpointSharedFact {
                created_at_ms: 1,
                workspace_id,
                user_authority_fact_id: [6; 32],
                endpoint_id: remote_endpoint,
                signing_public_key: [7; 32],
                endpoint_role: EndpointRole::Device,
                device_name: EndpointDeviceName::new("remote").expect("device name"),
                signer_id: [6; 32],
                signer_public_key: crypto::ed25519_public_key(&[17; 32]),
            },
        );
        store
            .write_transaction(|tx| {
                tx.insert_values_in_tx(&connection_row)?;
                tx.insert_values_in_tx(&endpoint_shared_row)?;
                Ok(())
            })
            .expect("seed typed rows");
        record_share(&store, workspace_id, &context_fact, Vec::new());
        record_share(&store, workspace_id, &owner_fact, vec![context_fact.id]);
        project_sync_range_setting(
            &store,
            500,
            sync::compare::fact::TimestampRange { start: 20, end: 20 },
        );

        let output =
            append_live_tail_send(RuntimeEffects::new(), &store, connection_id, &owner_fact)
                .expect("tail");

        assert_eq!(output.intents.len(), 1);
        let send =
            crate::protocol::connection::send_facts_on_connection::decode_send_facts_on_connection(
                &output.intents[0],
            )
            .expect("decode send");
        assert_eq!(send.connection_id, connection_id);
        assert_eq!(send.fact_ids, vec![context_fact.id, owner_fact.id]);

        project_sync_range_setting(
            &store,
            600,
            sync::compare::fact::TimestampRange { start: 30, end: 40 },
        );
        let out_of_range =
            append_live_tail_send(RuntimeEffects::new(), &store, connection_id, &owner_fact)
                .expect("tail out of range");
        assert!(out_of_range.intents.is_empty());
    }

    #[test]
    fn advertise_connection_shareable_facts_uses_local_sync_range_setting() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
            .expect("store");
        let connection_id = [8; 32];
        let range = sync::compare::fact::TimestampRange { start: 10, end: 20 };
        let row = connection::connection::connection_row(
            connection::connection::ConnectionRowFields::without_addresses(
                connection_id,
                [1; 32],
                [2; 32],
                [3; 32],
                [7; 32],
                [8; 32],
                [9; 32],
            ),
        )
        .expect("connection row");
        store
            .write_transaction(|tx| tx.insert_values_in_tx(&row).map(|_| ()))
            .expect("insert row");
        project_sync_range_setting(&store, 500, range);

        let output = advertise_connection_shareable_facts(&store, connection_id).expect("seed");

        assert_eq!(output.facts.len(), 1);
        let compare = sync::compare::project::decode::decode_fact(&output.facts[0].bytes)
            .expect("compare fact");
        assert_eq!(compare.connection_id, connection_id);
        assert_eq!(compare.range, range);
        assert!(compare.response_requested);
    }

    #[test]
    fn seed_connection_sync_handler_waits_until_connection_row_exists() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
            .expect("store");
        let intent = seed_connection_sync_intent(SeedConnectionSync {
            connection_id: [8; 32],
        });

        let output = SeedConnectionSyncHandler::new()
            .handle(&intent, &HandlerContext::new(&store))
            .expect("handle seed without row");

        assert!(output.facts.is_empty());
        assert!(output.intents.is_empty());
    }

    #[test]
    fn seed_connection_sync_intent_round_trips() {
        let input = SeedConnectionSync {
            connection_id: [7; 32],
        };
        let intent = seed_connection_sync_intent(input.clone());

        assert_eq!(decode_seed_connection_sync(&intent).unwrap(), input);
    }

    fn workspace_scope(workspace_id: FactId) -> FactScope {
        FactScope::Scoped {
            kind: ScopeKind::new("workspace").expect("scope kind"),
            id: workspace_id,
        }
    }

    fn record_share(store: &Db, workspace_id: FactId, fact: &Fact, context_have: Vec<FactId>) {
        shared_fact::record_sync_contribution(
            store,
            &ShareFactWithSync {
                workspace_id,
                owner_fact_id: fact.id,
                timestamp_ms: fact.timestamp,
                state: SyncShareState::Upsert,
                context_have,
            },
            Some(fact),
        )
        .expect("record share");
    }

    fn project_sync_range_setting(
        store: &Db,
        effective_at_ms: u64,
        range: sync::compare::fact::TimestampRange,
    ) {
        let fact = sync::local_setting::setting_fact(
            effective_at_ms,
            sync::local_setting::SyncSettingMode::Range(range),
        )
        .expect("setting fact");
        let output = sync::local_setting::SyncLocalSettingProjector::new()
            .project(&fact, &ProjectionContext::default())
            .expect("project setting");
        let rows = output
            .row_mutations
            .into_iter()
            .filter_map(|mutation| match mutation {
                ProjectedRowMutation::InsertValues(row) => Some(row),
                _ => None,
            })
            .collect::<Vec<_>>();
        store
            .write_transaction(|tx| {
                for row in &rows {
                    tx.insert_values_in_tx(row)?;
                }
                Ok(())
            })
            .expect("insert setting rows");
    }
}
