//! Sync share contribution intent layout.
//!
//! Fact projection emits `share_fact_with_sync` after decoding a fact and
//! validating any context it chooses to advertise as safe dependency context.
//! The handler is intentionally mechanical: it applies the supplied owner
//! contribution, records sync visibility, updates negentropy summaries, and
//! rejects local-only fact bytes. It does not parse raw selectors or infer
//! dependency closure from fact bodies.

use crate::core::{
    effects::PipelineEffects,
    fact_store::persisted_fact,
    facts::{Fact, FactId},
    intents::{HandlerContext, HandlerFactId, HandlerResult, Intent, IntentHandler, IntentKind},
    store::Store,
};
use crate::protocol::connection::send_facts_on_connection::{
    send_facts_on_connection_intent, SendFactsOnConnection,
};
use crate::protocol::payload::{PayloadError, PayloadReader, PayloadWriter};
use crate::protocol::sync::shared_fact;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

pub const SHARE_FACT_WITH_SYNC: &str = "share_fact_with_sync";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncShareState {
    Upsert,
    Retract,
}

impl SyncShareState {
    fn as_u8(self) -> u8 {
        match self {
            Self::Upsert => 1,
            Self::Retract => 2,
        }
    }

    fn from_u8(value: u8) -> Result<Self, String> {
        match value {
            1 => Ok(Self::Upsert),
            2 => Ok(Self::Retract),
            _ => Err("invalid share_fact_with_sync state".to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareFactWithSync {
    pub workspace_id: FactId,
    pub owner_fact_id: FactId,
    pub timestamp_ms: u64,
    pub state: SyncShareState,
    pub context_have: Vec<FactId>,
}

pub fn share_fact_with_sync_intent(mut input: ShareFactWithSync) -> Intent {
    input.context_have.sort();
    input.context_have.dedup();

    let mut payload =
        PayloadWriter::with_capacity(2 + 32 + 32 + 8 + 4 + input.context_have.len() * 32);
    payload.u8(1);
    payload.u8(input.state.as_u8());
    payload.fixed(&input.workspace_id);
    payload.fixed(&input.owner_fact_id);
    payload.u64be(input.timestamp_ms);
    payload.u32be(
        input
            .context_have
            .len()
            .try_into()
            .expect("context_have count fits u32"),
    );
    for fact_id in &input.context_have {
        payload.fixed(fact_id);
    }

    Intent::new(
        IntentKind::new(SHARE_FACT_WITH_SYNC).expect("valid share_fact_with_sync kind"),
        share_fact_with_sync_key(&input),
        payload.finish(),
    )
}

pub fn share_fact_with_sync_intent_for_fact(
    workspace_id: FactId,
    fact_id: FactId,
    timestamp_ms: u64,
    context_have: Vec<FactId>,
) -> Intent {
    share_fact_with_sync_intent(ShareFactWithSync {
        workspace_id,
        owner_fact_id: fact_id,
        timestamp_ms,
        state: SyncShareState::Upsert,
        context_have,
    })
}

pub fn retract_fact_from_sync_intent(
    workspace_id: FactId,
    fact_id: FactId,
    timestamp_ms: u64,
) -> Intent {
    share_fact_with_sync_intent(ShareFactWithSync {
        workspace_id,
        owner_fact_id: fact_id,
        timestamp_ms,
        state: SyncShareState::Retract,
        context_have: Vec::new(),
    })
}

pub fn decode_share_fact_with_sync(intent: &Intent) -> Result<ShareFactWithSync, String> {
    if intent.kind.as_str() != SHARE_FACT_WITH_SYNC {
        return Err("expected share_fact_with_sync intent".into());
    }
    let mut reader = PayloadReader::new(&intent.payload);
    reader.expect_u8(1).map_err(payload_error)?;
    let state = SyncShareState::from_u8(reader.u8().map_err(payload_error)?)?;
    let workspace_id = reader.array::<32>().map_err(payload_error)?;
    let owner_fact_id = reader.array::<32>().map_err(payload_error)?;
    let timestamp_ms = reader.u64be().map_err(payload_error)?;
    let count = reader.u32be().map_err(payload_error)? as usize;
    let mut context_have = Vec::with_capacity(count);
    for _ in 0..count {
        context_have.push(reader.array::<32>().map_err(payload_error)?);
    }
    reader.finish().map_err(payload_error)?;
    context_have.sort();
    context_have.dedup();
    let input = ShareFactWithSync {
        workspace_id,
        owner_fact_id,
        timestamp_ms,
        state,
        context_have,
    };
    if intent.key != share_fact_with_sync_key(&input) {
        return Err("share_fact_with_sync idempotence key does not match payload".into());
    }
    Ok(input)
}

fn share_fact_with_sync_key(input: &ShareFactWithSync) -> Vec<u8> {
    let mut hash = blake3::Hasher::new();
    hash.update(b"topo:sync:share-fact-with-sync:v1:");
    hash.update(&[input.state.as_u8()]);
    hash.update(&input.workspace_id);
    hash.update(&input.owner_fact_id);
    hash.update(&input.timestamp_ms.to_be_bytes());
    for fact_id in &input.context_have {
        hash.update(fact_id);
    }
    hash.finalize().as_bytes().to_vec()
}

fn payload_error(err: PayloadError) -> String {
    format!("invalid share_fact_with_sync payload: {err}")
}

#[derive(Debug, Clone, Default)]
pub struct ShareFactWithSyncHandler;

impl ShareFactWithSyncHandler {
    pub fn new() -> Self {
        Self
    }
}

impl IntentHandler for ShareFactWithSyncHandler {
    fn input_fact_ids(&self, intent: &Intent) -> Result<Vec<HandlerFactId>, String> {
        let input = decode_share_fact_with_sync(intent)?;
        Ok(match input.state {
            SyncShareState::Upsert => vec![input.owner_fact_id],
            SyncShareState::Retract => Vec::new(),
        })
    }

    fn handle(&self, raw: &Intent, context: &HandlerContext) -> HandlerResult {
        let input = decode_share_fact_with_sync(raw)?;
        match input.state {
            SyncShareState::Upsert => {
                let owner = context.require_fact(&input.owner_fact_id)?;
                context.require_non_local_fact_bytes(&input.owner_fact_id)?;
                // Context links came from projector-validated offers. A context fact may
                // already be purged by the time this queued handler runs.
                for fact_id in &input.context_have {
                    let Some(fact) = persisted_fact(context.store()?, fact_id)? else {
                        continue;
                    };
                    HandlerContext::with_facts([fact]).require_non_local_fact_bytes(fact_id)?;
                }
                let plan =
                    shared_fact::plan_sync_contribution(context.store()?, &input, Some(owner))?;
                let mut output = PipelineEffects::new();
                output.row_mutations.extend(plan.row_mutations);
                if plan.changed {
                    let excluded =
                        crate::protocol::connection::fact_receipt::origin_connection_ids_for_fact(
                            context.store()?,
                            input.owner_fact_id,
                        )?
                        .into_iter()
                        .collect::<BTreeSet<_>>();
                    advertise_planned_share_to_connections_except(
                        output,
                        context.store()?,
                        input.workspace_id,
                        owner,
                        &plan.context_have,
                        &excluded,
                    )
                } else {
                    Ok(output)
                }
            }
            SyncShareState::Retract => {
                let plan = shared_fact::plan_sync_contribution(context.store()?, &input, None)?;
                let mut output = PipelineEffects::new();
                output.row_mutations.extend(plan.row_mutations);
                Ok(output)
            }
        }
    }
}

fn advertise_planned_share_to_connections_except(
    mut output: PipelineEffects,
    store: &Store,
    workspace_id: FactId,
    owner: &Fact,
    context_have: &[FactId],
    excluded_connection_ids: &BTreeSet<FactId>,
) -> HandlerResult {
    for connection_id in shared_fact::connection_ids_authorized_for_workspace(store, workspace_id)?
    {
        if excluded_connection_ids.contains(&connection_id) {
            continue;
        }
        output = output.intent(send_facts_on_connection_intent(SendFactsOnConnection {
            connection_id,
            fact_ids: planned_live_tail_fact_ids(
                store,
                connection_id,
                workspace_id,
                owner,
                context_have,
            )?,
        }));
    }
    Ok(output)
}

fn planned_live_tail_fact_ids(
    store: &Store,
    connection_id: FactId,
    workspace_id: FactId,
    owner: &Fact,
    context_have: &[FactId],
) -> Result<Vec<FactId>, String> {
    let available = shared_fact::shareable_facts_for_connection(store, connection_id)?
        .into_iter()
        .map(|fact| (fact.id, fact))
        .collect::<BTreeMap<_, _>>();
    let mut selected = BTreeSet::<FactId>::new();
    let mut pending = VecDeque::<FactId>::new();
    for fact_id in context_have {
        if available.contains_key(fact_id) && selected.insert(*fact_id) {
            pending.push_back(*fact_id);
        }
    }
    while let Some(fact_id) = pending.pop_front() {
        for dep_id in shared_fact::negentropy_context_have_for_leaf(store, workspace_id, fact_id)? {
            if available.contains_key(&dep_id) && selected.insert(dep_id) {
                pending.push_back(dep_id);
            }
        }
    }

    let mut facts = selected
        .into_iter()
        .filter_map(|fact_id| available.get(&fact_id).cloned())
        .collect::<Vec<_>>();
    facts.push(owner.clone());
    facts.sort_by_key(|fact| (fact.timestamp, fact.id));
    let mut fact_ids = facts.into_iter().map(|fact| fact.id).collect::<Vec<_>>();
    fact_ids.dedup();
    Ok(fact_ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto;
    use crate::core::facts::{Fact, FactId, FactScope, ScopeKind};
    use crate::core::intents::{HandlerContext, IntentHandler};
    use crate::core::pipeline::commit_pipeline_effects_to_store;
    use crate::core::schema::CORE_SCHEMA_SOURCE;
    use crate::core::store::{Store, TableName};
    use crate::protocol::auth::endpoint::{fact::EndpointFact, rows as endpoint_rows};
    use crate::protocol::auth::endpoint_shared::{
        fact::{EndpointDeviceName, EndpointRole, EndpointSharedFact},
        rows as endpoint_shared_rows,
    };
    use crate::protocol::connection;
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;

    #[test]
    fn share_fact_with_sync_suppresses_live_tail_to_origin_connection() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("store");
        let workspace_id = [9; 32];
        let local_secret = [11; 32];
        let local_endpoint = crypto::x25519_public_key(&local_secret);
        let remote_endpoint = [2; 32];
        let origin_connection_id = [3; 32];
        let other_connection_id = [4; 32];
        let owner = Fact::new(
            FactScope::Scoped {
                kind: ScopeKind::new("workspace").unwrap(),
                id: workspace_id,
            },
            42,
            vec![99],
        );
        let mut rows = endpoint_rows::endpoint_rows(&EndpointFact {
            endpoint: local_endpoint,
            secret: local_secret,
            signing_public_key: crypto::ed25519_public_key(&[13; 32]),
            signing_secret: [13; 32],
        });
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
        for connection_id in [origin_connection_id, other_connection_id] {
            rows.push(
                connection::response::rows::connection_response_row(
                    connection_id,
                    &connection::response::fact::ConnectionResponseFact {
                        from_endpoint: local_endpoint,
                        to_endpoint: remote_endpoint,
                        request_id: [8; 32],
                        invite_secret_fact_id: [9; 32],
                        initiator_ephemeral_secret_fact_id: [10; 32],
                        responder_ephemeral_secret_fact_id: [11; 32],
                        responder_ephemeral_public_key: [12; 32],
                        handshake_hash: [13; 32],
                        connection_secret: [14; 32],
                    },
                )
                .expect("connection row"),
            );
        }
        rows.push(connection::fact_receipt::rows::connection_fact_receipt_row(
            [15; 32],
            &connection::fact_receipt::fact::ConnectionFactReceipt {
                received_fact_id: owner.id,
                origin_addr: connection::fact_receipt::fact::OriginAddr::new(b"127.0.0.1:1")
                    .expect("origin addr"),
                local_endpoint_id: local_endpoint,
                sender_endpoint_id: remote_endpoint,
                receive_path: connection::fact_receipt::fact::RECEIVE_PATH_CONNECTION_FRAME,
                connection_id: Some(origin_connection_id),
                request_id: Some([8; 32]),
                frame_hash: [16; 32],
                received_at_local_ms: 43,
            },
        ));
        store.insert_table_rows(rows).expect("seed rows");

        let intent = share_fact_with_sync_intent_for_fact(
            workspace_id,
            owner.id,
            owner.timestamp,
            Vec::new(),
        );
        let output = ShareFactWithSyncHandler::new()
            .handle(
                &intent,
                &HandlerContext::with_facts([owner.clone()]).with_store(&store),
            )
            .expect("share with sync");

        assert!(!output.row_mutations.is_empty());
        assert!(shared_fact::shareable_fact_rows(&store)
            .expect("precommit shareable rows")
            .is_empty());
        assert_eq!(output.intents.len(), 1);
        let send = connection::send_facts_on_connection::decode_send_facts_on_connection(
            &output.intents[0],
        )
        .expect("send facts intent");
        assert_eq!(send.connection_id, other_connection_id);
        assert_eq!(send.fact_ids, vec![owner.id]);

        commit_pipeline_effects_to_store(
            &store,
            &output,
            &sync_contribution_tables(),
            "commit share_fact_with_sync handler output",
        )
        .expect("commit effects");
        assert_eq!(
            shared_fact::shareable_fact_rows(&store)
                .expect("postcommit shareable rows")
                .len(),
            1
        );
    }

    #[test]
    fn share_fact_with_sync_live_tail_includes_existing_context_without_precommit_index() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
                .expect("store");
        let workspace_id = [9; 32];
        let local_secret = [11; 32];
        let local_endpoint = crypto::x25519_public_key(&local_secret);
        let remote_endpoint = [2; 32];
        let connection_id = [4; 32];
        let root_context_fact = Fact::new(workspace_scope(workspace_id), 5, vec![99, 0]);
        let context_fact = Fact::new(workspace_scope(workspace_id), 10, vec![99, 1]);
        let owner = Fact::new(workspace_scope(workspace_id), 20, vec![99, 2]);

        store
            .write_transaction(|tx| {
                crate::core::fact_store::insert_fact_and_pending_in_tx(tx, &root_context_fact)?;
                crate::core::fact_store::insert_fact_and_pending_in_tx(tx, &context_fact)?;
                crate::core::fact_store::insert_fact_and_pending_in_tx(tx, &owner)?;
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
        rows.push(
            connection::response::rows::connection_response_row(
                connection_id,
                &connection::response::fact::ConnectionResponseFact {
                    from_endpoint: local_endpoint,
                    to_endpoint: remote_endpoint,
                    request_id: [8; 32],
                    invite_secret_fact_id: [9; 32],
                    initiator_ephemeral_secret_fact_id: [10; 32],
                    responder_ephemeral_secret_fact_id: [11; 32],
                    responder_ephemeral_public_key: [12; 32],
                    handshake_hash: [13; 32],
                    connection_secret: [14; 32],
                },
            )
            .expect("connection row"),
        );
        store.insert_table_rows(rows).expect("seed rows");
        shared_fact::record_sync_contribution(
            &store,
            &ShareFactWithSync {
                workspace_id,
                owner_fact_id: root_context_fact.id,
                timestamp_ms: root_context_fact.timestamp,
                state: SyncShareState::Upsert,
                context_have: Vec::new(),
            },
            Some(&root_context_fact),
        )
        .expect("record root context share");
        shared_fact::record_sync_contribution(
            &store,
            &ShareFactWithSync {
                workspace_id,
                owner_fact_id: context_fact.id,
                timestamp_ms: context_fact.timestamp,
                state: SyncShareState::Upsert,
                context_have: vec![root_context_fact.id],
            },
            Some(&context_fact),
        )
        .expect("record context share");

        let intent = share_fact_with_sync_intent_for_fact(
            workspace_id,
            owner.id,
            owner.timestamp,
            vec![context_fact.id],
        );
        let output = ShareFactWithSyncHandler::new()
            .handle(
                &intent,
                &HandlerContext::with_facts([owner.clone()]).with_store(&store),
            )
            .expect("share with sync");

        assert_eq!(
            shared_fact::shareable_fact_rows(&store)
                .expect("precommit shareable rows")
                .len(),
            2
        );
        let send = connection::send_facts_on_connection::decode_send_facts_on_connection(
            &output.intents[0],
        )
        .expect("send facts intent");
        assert_eq!(send.connection_id, connection_id);
        assert_eq!(
            send.fact_ids,
            vec![root_context_fact.id, context_fact.id, owner.id]
        );
    }

    fn workspace_scope(workspace_id: FactId) -> FactScope {
        FactScope::Scoped {
            kind: ScopeKind::new("workspace").unwrap(),
            id: workspace_id,
        }
    }

    fn sync_contribution_tables() -> [TableName; 4] {
        [
            shared_fact::SHAREABLE_FACT_ROWS,
            shared_fact::NEGENTROPY_LEAF_ROWS,
            shared_fact::NEGENTROPY_CONTEXT_HAVE_ROWS,
            shared_fact::NEGENTROPY_NODE_ROWS,
        ]
    }
}
