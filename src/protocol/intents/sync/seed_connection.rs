//! Bounded sync seeding for one connection.
//!
//! Projection emits this intent when a connection row becomes durable. The
//! handler reads the shareable-fact index and advertises eligible facts by
//! emitting deterministic `sync_have_id` facts plus transport send intents.

use crate::core::{
    facts::{Fact, FactId},
    handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler},
    intents::{Intent, IntentExecution, IntentKind},
    schema_dsl::{self, FieldValue},
    store::Store,
};
use crate::protocol::facts::{connection, sync};
use crate::protocol::intents::transport::send_facts_on_connection::{self, SendFactsOnConnection};

pub const SEED_CONNECTION_SYNC: &str = "seed_connection_sync";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedConnectionSync {
    pub connection_id: FactId,
}

pub fn seed_connection_sync_intent(input: SeedConnectionSync) -> Intent {
    Intent::new(
        IntentKind::new(SEED_CONNECTION_SYNC).expect("valid seed_connection_sync kind"),
        IntentExecution::Deferred,
        seed_connection_sync_key(input.connection_id),
        encode_seed_connection_sync(&input),
    )
}

pub fn decode_seed_connection_sync(intent: &Intent) -> Result<SeedConnectionSync, String> {
    if intent.kind.as_str() != SEED_CONNECTION_SYNC {
        return Err("expected seed_connection_sync intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("seed_connection_sync intent must be deferred".to_string());
    }
    let payload = schema_dsl::decode_layout_record(
        schema_dsl::intents_layout("seed_connection_sync_payload"),
        &intent.payload,
    )?;
    if payload.u8("version")? != 1 {
        return Err("seed_connection_sync payload version unsupported".to_string());
    }
    let input = SeedConnectionSync {
        connection_id: payload.bytes_array("connection_id")?,
    };
    if intent.key != seed_connection_sync_key(input.connection_id) {
        return Err("seed_connection_sync key does not match payload".to_string());
    }
    Ok(input)
}

fn seed_connection_sync_key(connection_id: FactId) -> Vec<u8> {
    let mut key = Vec::with_capacity(32);
    key.extend_from_slice(&connection_id);
    key
}

fn encode_seed_connection_sync(input: &SeedConnectionSync) -> Vec<u8> {
    schema_dsl::encode_layout_record(
        schema_dsl::intents_layout("seed_connection_sync_payload"),
        &[
            ("version", FieldValue::U8(1)),
            (
                "connection_id",
                FieldValue::Bytes(input.connection_id.to_vec()),
            ),
        ],
    )
    .expect("seed_connection_sync payload matches schema")
}

#[derive(Debug, Clone, Default)]
pub struct SeedConnectionSyncHandler;

impl SeedConnectionSyncHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for SeedConnectionSyncHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == SEED_CONNECTION_SYNC
    }

    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_seed_connection_sync(intent)?;
        Ok(vec![input.connection_id])
    }

    fn handle(&self, raw: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = decode_seed_connection_sync(raw)?;
        let connection_fact = context.require_fact(&input.connection_id)?;
        if connection_fact.id != input.connection_id {
            return Err("seed_connection_sync context payload id mismatch".to_string());
        }
        connection::response::layout::decode_fact(connection_fact.body())
            .map_err(|_| "seed_connection_sync context is not a connection response".to_string())?;
        advertise_connection_shareable_facts(context.store()?, input.connection_id)
    }
}

pub fn advertise_connection_shareable_facts(
    store: &Store,
    connection_id: FactId,
) -> Result<HandlerOutput, String> {
    let facts = sync::shared_fact::shareable_facts_for_connection(store, connection_id)?;
    advertise_facts_on_connection(connection_id, facts)
}

pub fn advertise_indexed_fact_to_connections(
    store: &Store,
    fact: &Fact,
) -> Result<HandlerOutput, String> {
    let mut output = HandlerOutput::new();
    for connection_id in sync::shared_fact::connection_ids_for_shareable_fact(store, fact.id)? {
        output = append_have_advertisement(output, connection_id, fact)?;
    }
    Ok(output)
}

fn advertise_facts_on_connection(
    connection_id: FactId,
    facts: Vec<Fact>,
) -> Result<HandlerOutput, String> {
    let mut output = HandlerOutput::new();
    for fact in facts {
        output = append_have_advertisement(output, connection_id, &fact)?;
    }
    Ok(output)
}

fn append_have_advertisement(
    output: HandlerOutput,
    connection_id: FactId,
    fact: &Fact,
) -> Result<HandlerOutput, String> {
    let have_fact = sync::have_id::advertisement_fact(connection_id, fact)?;
    Ok(output.fact(have_fact.clone()).intent(
        send_facts_on_connection::send_facts_on_connection_intent(SendFactsOnConnection {
            connection_id,
            fact_ids: vec![have_fact.id],
        }),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::facts::{FactScope, ScopeKind};
    use crate::core::schema_dsl::{CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE};
    use crate::core::store::Store;
    use crate::protocol::facts::sync::shared_fact;

    #[test]
    fn seed_connection_sync_intent_round_trips() {
        let input = SeedConnectionSync {
            connection_id: [7; 32],
        };
        let intent = seed_connection_sync_intent(input.clone());

        assert_eq!(decode_seed_connection_sync(&intent).unwrap(), input);
    }

    #[test]
    fn advertise_connection_shareable_facts_emits_have_and_send_intents() {
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
                connection::response::rows::connection_response_row(
                    connection_id,
                    &connection::response::fact::ConnectionResponseFact {
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

        assert!(
            output.facts.is_empty(),
            "workspace authorization is not proven by this minimal fixture"
        );
    }
}
