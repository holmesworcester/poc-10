//! Send the fact requested by a sync need-id fact.

use crate::core::handler_dispatch::{HandlerContext, HandlerFactId, HandlerOutput, IntentHandler};
use crate::core::intents::{Intent, IntentExecution, IntentKind};
use crate::core::schema_dsl::{self, FieldValue};
use crate::protocol::facts::sync::need_id;
use crate::protocol::intents::transport::send_facts_on_connection::{
    send_facts_on_connection_intent, SendFactsOnConnection,
};

pub const SEND_REQUESTED_FACT: &str = "send_requested_fact";

pub type HandlerId = [u8; 32];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendRequestedFact {
    pub need_fact_id: HandlerId,
}

pub fn send_requested_fact_intent(input: SendRequestedFact) -> Intent {
    let payload = schema_dsl::encode_layout_record(
        schema_dsl::intents_layout("send_requested_fact_payload"),
        &[
            ("version", FieldValue::U8(1)),
            (
                "need_fact_id",
                FieldValue::Bytes(input.need_fact_id.to_vec()),
            ),
        ],
    )
    .expect("send_requested_fact payload matches schema");
    Intent::new(
        IntentKind::new(SEND_REQUESTED_FACT).expect("valid send_requested_fact kind"),
        IntentExecution::Deferred,
        send_requested_fact_key(&input),
        payload,
    )
}

pub fn decode_send_requested_fact(intent: &Intent) -> Result<SendRequestedFact, String> {
    if intent.kind.as_str() != SEND_REQUESTED_FACT {
        return Err("expected send_requested_fact intent".to_string());
    }
    if intent.execution != IntentExecution::Deferred {
        return Err("send_requested_fact intent must be deferred".to_string());
    }
    let payload = schema_dsl::decode_layout_record(
        schema_dsl::intents_layout("send_requested_fact_payload"),
        &intent.payload,
    )?;
    if payload.u8("version")? != 1 {
        return Err("send_requested_fact payload version unsupported".to_string());
    }
    let need_fact_id = payload.bytes_array("need_fact_id")?;
    let input = SendRequestedFact { need_fact_id };
    if intent.key != send_requested_fact_key(&input) {
        return Err("send_requested_fact idempotence key does not match payload".to_string());
    }
    Ok(input)
}

fn send_requested_fact_key(input: &SendRequestedFact) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:sync:send-requested-fact:v1:");
    hash.update(&input.need_fact_id);
    hash.finalize().as_bytes().to_vec()
}

#[derive(Debug, Clone, Default)]
pub struct SendRequestedFactHandler;

impl SendRequestedFactHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for SendRequestedFactHandler {
    fn accepts(&self, intent: &Intent) -> bool {
        intent.kind.as_str() == SEND_REQUESTED_FACT
    }

    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_send_requested_fact(intent)?;
        Ok(vec![input.need_fact_id])
    }

    fn handle(&self, raw: &Intent, context: &HandlerContext) -> Result<HandlerOutput, String> {
        let input = decode_send_requested_fact(raw)?;
        let need_fact = context.require_fact(&input.need_fact_id)?;
        let need = need_id::layout::decode_fact(&need_fact.bytes)?;
        let Some(fact) = crate::core::wake_loop::persisted_fact(context.store()?, &need.fact_id)?
        else {
            return Ok(HandlerOutput::new());
        };
        if crate::protocol::facts::sync::shared_fact::shareable_fact_for_connection(
            context.store()?,
            need.connection_id,
            need.fact_id,
        )?
        .is_none()
        {
            return Ok(HandlerOutput::new());
        }
        crate::protocol::facts::transport::transit::create::require_sendable_fact(&fact)?;
        Ok(
            HandlerOutput::new().intent(send_facts_on_connection_intent(SendFactsOnConnection {
                connection_id: need.connection_id,
                fact_ids: vec![need.fact_id],
            })),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto;
    use crate::core::facts::Fact;
    use crate::core::handler_dispatch::IntentHandler;
    use crate::core::schema_dsl::{CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE};
    use crate::core::store::Store;
    use crate::core::wake_loop::WakeLoop;
    use crate::protocol::facts::connection;
    use crate::protocol::facts::identity;
    use crate::protocol::facts::sync::need_id::fact::SyncNeedIdFact;
    use crate::protocol::facts::sync::need_id::layout as sync_need_id_layout;
    use crate::protocol::facts::sync::shared_fact::{shareable_fact_row, ShareableFactRow};
    use crate::protocol::intents::transport::send_facts_on_connection;

    #[test]
    fn send_requested_fact_ignores_unshared_persisted_fact() {
        let workspace_id = [9; 32];
        let requested = workspace_fact(workspace_id, 50, 1_250);
        let need_fact = sync_need_fact([31; 32], requested.id);
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("store");
        seed_shareable_connection(&store, [31; 32], workspace_id);
        persist_facts(&store, [requested]);
        let intent = send_requested_fact_intent(SendRequestedFact {
            need_fact_id: need_fact.id,
        });

        let output = SendRequestedFactHandler::new()
            .handle(
                &intent,
                &HandlerContext::with_facts([need_fact]).with_store(&store),
            )
            .expect("handle request");

        assert!(output.intents.is_empty());
    }

    #[test]
    fn send_requested_fact_sends_fact_from_shareable_index() {
        let workspace_id = [9; 32];
        let requested = workspace_fact(workspace_id, 50, 1_250);
        let need_fact = sync_need_fact([31; 32], requested.id);
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("store");
        seed_shareable_connection(&store, [31; 32], workspace_id);
        persist_facts(&store, [requested.clone()]);
        share_fact(&store, workspace_id, &requested);
        let intent = send_requested_fact_intent(SendRequestedFact {
            need_fact_id: need_fact.id,
        });

        let output = SendRequestedFactHandler::new()
            .handle(
                &intent,
                &HandlerContext::with_facts([need_fact]).with_store(&store),
            )
            .expect("handle request");

        assert_eq!(output.intents.len(), 1);
        let send = send_facts_on_connection::decode_send_facts_on_connection(&output.intents[0])
            .expect("decode send");
        assert_eq!(send.connection_id, [31; 32]);
        assert_eq!(send.fact_ids, vec![requested.id]);
    }

    fn sync_need_fact(connection_id: [u8; 32], fact_id: [u8; 32]) -> Fact {
        Fact::new(
            crate::core::facts::FactScope::Global,
            2_000,
            sync_need_id_layout::encode_fact(&SyncNeedIdFact {
                connection_id,
                fact_id,
            })
            .expect("encode need-id"),
        )
    }

    fn workspace_fact(workspace_id: [u8; 32], seed: u8, timestamp: u64) -> Fact {
        let mut bytes = vec![250, seed];
        bytes.extend_from_slice(&workspace_id);
        Fact::new(
            crate::protocol::matchers::workspace_scope(workspace_id),
            timestamp,
            bytes,
        )
    }

    fn persist_facts(store: &Store, facts: impl IntoIterator<Item = Fact>) {
        let mut bus = WakeLoop::new();
        for fact in facts {
            bus.submit_fact(fact);
        }
        bus.save(store).expect("persist facts");
    }

    fn share_fact(store: &Store, workspace_id: [u8; 32], fact: &Fact) {
        store
            .insert_table_rows(vec![shareable_fact_row(ShareableFactRow {
                workspace_id,
                fact_id: fact.id,
                timestamp_ms: fact.timestamp,
            })])
            .expect("share fact row");
    }

    fn seed_shareable_connection(store: &Store, connection_id: [u8; 32], workspace_id: [u8; 32]) {
        let local_secret = [0x11; 32];
        let signing_secret = [0x12; 32];
        let local_endpoint = crypto::x25519_public_key(&local_secret);
        let remote_endpoint = [0x13; 32];
        let local = identity::endpoint::fact::EndpointFact {
            endpoint: local_endpoint,
            secret: local_secret,
            signing_public_key: crypto::ed25519_public_key(&signing_secret),
            signing_secret,
        };
        let connection = connection::response::fact::ConnectionResponseFact {
            from_endpoint: local_endpoint,
            to_endpoint: remote_endpoint,
            request_id: [0x21; 32],
            invite_secret_fact_id: [0x22; 32],
            initiator_ephemeral_secret_fact_id: [0x23; 32],
            responder_ephemeral_secret_fact_id: [0x24; 32],
            responder_ephemeral_public_key: [0x25; 32],
            handshake_hash: [0x26; 32],
            connection_secret: [0x27; 32],
        };
        let endpoint_shared = identity::endpoint_shared::fact::EndpointSharedFact {
            created_at_ms: 1,
            workspace_id,
            user_authority_fact_id: [0x31; 32],
            endpoint_id: remote_endpoint,
            signing_public_key: [0x32; 32],
            endpoint_role: identity::endpoint_shared::fact::EndpointRole::Device,
            device_name: "remote".to_string(),
        };
        let mut rows = identity::endpoint::rows::endpoint_rows(&local);
        rows.push(
            connection::response::rows::connection_response_row(connection_id, &connection)
                .expect("connection row"),
        );
        rows.push(
            identity::endpoint_shared::rows::endpoint_shared_row([0x33; 32], &endpoint_shared)
                .expect("endpoint shared row"),
        );
        store.insert_table_rows(rows).expect("seed connection");
    }
}
