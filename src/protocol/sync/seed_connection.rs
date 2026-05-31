//! Bounded sync seeding for one connection.
//!
//! Projection emits this intent when a connection row becomes durable. The
//! handler reads the connection-scoped shareable-fact index, sends one root
//! negentropy compare for the initial round, and coalesces newly shareable
//! facts into timestamp-bucket tail sends.

use crate::core::effects::PipelineEffects;
use crate::core::{
    facts::{Fact, FactId},
    intents::{
        HandlerContext, HandlerError, HandlerFactId, HandlerResult, Intent, IntentHandler,
        IntentKind,
    },
    store::Store,
};
use crate::protocol::connection::send_facts_on_connection::{
    send_facts_on_connection_intent, SendFactsOnConnection,
};
use crate::protocol::{connection, sync};
use std::collections::BTreeSet;

pub const SEED_CONNECTION_SYNC: &str = "seed_connection_sync";

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
    if intent.key != seed_connection_sync_key(input.connection_id) {
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
    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_seed_connection_sync(intent)?;
        Ok(vec![input.connection_id])
    }

    fn handle(&self, raw: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_seed_connection_sync(raw)?;
        let Some(connection_fact) = context.fact(&input.connection_id) else {
            return Ok(PipelineEffects::new());
        };
        if connection_fact.id != input.connection_id {
            return Err("seed_connection_sync context payload id mismatch".into());
        }
        connection::bootstrap_response::layout::decode_fact(connection_fact.body()).map_err(|_| {
            HandlerError::fatal("seed_connection_sync context is not a connection response")
        })?;
        advertise_connection_shareable_facts(context.store()?, input.connection_id)
    }
}

pub fn advertise_connection_shareable_facts(store: &Store, connection_id: FactId) -> HandlerResult {
    let summary = sync::shared_fact::range_summary_for_connection(
        store,
        connection_id,
        sync::compare::fact::TimestampRange::ROOT,
    )?;
    let compare = sync::compare::create::start_compare_fact_with_summary(connection_id, summary)?;
    Ok(PipelineEffects::new()
        .fact(compare.clone())
        .intent(send_facts_on_connection_intent(SendFactsOnConnection {
            connection_id,
            fact_ids: vec![compare.id],
        })))
}

pub fn advertise_indexed_fact_to_connections(store: &Store, fact: &Fact) -> HandlerResult {
    advertise_indexed_fact_to_connections_except(store, fact, &BTreeSet::new())
}

pub fn advertise_indexed_fact_to_connections_except(
    store: &Store,
    fact: &Fact,
    excluded_connection_ids: &BTreeSet<FactId>,
) -> HandlerResult {
    let mut output = PipelineEffects::new();
    for connection_id in sync::shared_fact::connection_ids_for_shareable_fact(store, fact)? {
        if excluded_connection_ids.contains(&connection_id) {
            continue;
        }
        output = append_live_tail_send(output, store, connection_id, fact)?;
    }
    Ok(output)
}

fn append_live_tail_send(
    output: PipelineEffects,
    store: &Store,
    connection_id: FactId,
    fact: &Fact,
) -> HandlerResult {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto;
    use crate::core::facts::{FactScope, ScopeKind};
    use crate::core::schema::CORE_SCHEMA_SOURCE;
    use crate::core::store::Store;
    use crate::protocol::auth::endpoint::{fact::EndpointFact, rows as endpoint_rows};
    use crate::protocol::auth::endpoint_shared::{
        fact::{EndpointDeviceName, EndpointRole, EndpointSharedFact},
        rows as endpoint_shared_rows,
    };
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;
    use crate::protocol::sync::share_fact_with_sync::{ShareFactWithSync, SyncShareState};
    use crate::protocol::sync::shared_fact;

    #[test]
    fn seed_connection_sync_intent_round_trips() {
        let input = SeedConnectionSync {
            connection_id: [7; 32],
        };
        let intent = seed_connection_sync_intent(input.clone());

        assert_eq!(decode_seed_connection_sync(&intent).unwrap(), input);
    }

    #[test]
    fn advertise_connection_shareable_facts_emits_root_compare_and_send_intent() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
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
        store
            .insert_table_rows(vec![
                connection::bootstrap_response::rows::bootstrap_response_row(
                    connection_id,
                    &connection::bootstrap_response::fact::BootstrapResponseFact {
                        from_endpoint: [1; 32],
                        to_endpoint: [2; 32],
                        request_id: [3; 32],
                        invite_secret_fact_id: [4; 32],
                        initiator_ephemeral_secret_fact_id: [5; 32],
                        responder_ephemeral_secret_fact_id: [6; 32],
                        responder_ephemeral_public_key: [7; 32],
                        handshake_hash: [8; 32],
                        connection_secret: [9; 32],
                    },
                )
                .expect("connection row"),
                shared_fact::shareable_fact_row(shared_fact::ShareableFactRow {
                    workspace_id,
                    fact_id: fact.id,
                    timestamp_ms: fact.timestamp,
                }),
            ])
            .expect("insert rows");

        let output = advertise_connection_shareable_facts(&store, connection_id).expect("seed");

        assert_eq!(output.facts.len(), 1);
        let compare =
            sync::compare::layout::decode_fact(&output.facts[0].bytes).expect("compare fact");
        assert_eq!(compare.connection_id, connection_id);
        assert_eq!(compare.range, sync::compare::fact::TimestampRange::ROOT);
        assert!(compare.response_requested);
        assert_eq!(output.intents.len(), 1);
    }

    #[test]
    fn live_tail_send_expands_projector_context_for_trigger_fact() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
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
                crate::core::fact_store::insert_fact_and_pending_in_tx(tx, &context_fact)?;
                crate::core::fact_store::insert_fact_and_pending_in_tx(tx, &owner_fact)?;
                Ok(())
            })
            .expect("persist facts");
        let mut rows = endpoint_rows::endpoint_rows(&EndpointFact {
            endpoint: local_endpoint,
            secret: local_secret,
            signing_public_key: crypto::ed25519_public_key(&[13; 32]),
            signing_secret: [13; 32],
        });
        rows.push(
            connection::bootstrap_response::rows::bootstrap_response_row(
                connection_id,
                &connection::bootstrap_response::fact::BootstrapResponseFact {
                    from_endpoint: local_endpoint,
                    to_endpoint: remote_endpoint,
                    request_id: [3; 32],
                    invite_secret_fact_id: [4; 32],
                    initiator_ephemeral_secret_fact_id: [5; 32],
                    responder_ephemeral_secret_fact_id: [6; 32],
                    responder_ephemeral_public_key: [7; 32],
                    handshake_hash: [8; 32],
                    connection_secret: [9; 32],
                },
            )
            .expect("connection row"),
        );
        rows.push(
            endpoint_shared_rows::endpoint_shared_row(
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
                    signature: [18; crypto::ED25519_SIGNATURE_BYTES],
                },
            )
            .expect("endpoint shared row"),
        );
        store.insert_table_rows(rows).expect("seed rows");
        record_share(&store, workspace_id, &context_fact, Vec::new());
        record_share(&store, workspace_id, &owner_fact, vec![context_fact.id]);

        let output =
            append_live_tail_send(PipelineEffects::new(), &store, connection_id, &owner_fact)
                .expect("tail");

        assert_eq!(output.intents.len(), 1);
        let send =
            crate::protocol::connection::send_facts_on_connection::decode_send_facts_on_connection(
                &output.intents[0],
            )
            .expect("decode send");
        assert_eq!(send.connection_id, connection_id);
        assert_eq!(send.fact_ids, vec![context_fact.id, owner_fact.id]);
    }

    fn workspace_scope(workspace_id: FactId) -> FactScope {
        FactScope::Scoped {
            kind: ScopeKind::new("workspace").expect("scope kind"),
            id: workspace_id,
        }
    }

    fn record_share(store: &Store, workspace_id: FactId, fact: &Fact, context_have: Vec<FactId>) {
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
}
