//! Sync share contribution intent layout.
//!
//! Fact projection emits `share_fact_with_sync` after decoding a fact and
//! validating any context it chooses to advertise as safe dependency context.
//! The handler is intentionally mechanical: it applies the supplied owner
//! contribution, records sync visibility, updates negentropy summaries, and
//! rejects local-only fact bytes. It does not parse raw selectors or infer
//! dependency closure from fact bodies.

use crate::core::{
    facts::FactId,
    intents::{HandlerContext, HandlerError, HandlerResult, Intent, IntentHandler, IntentKind},
    wire::{Reader as PayloadReader, WireError as PayloadError, Writer as PayloadWriter},
};
use crate::protocol::sync::{seed_connection, shared_fact};

pub const SHARE_FACT_WITH_SYNC: &str = "share_fact_with_sync";

pub const STORAGE_VERSION: u32 = crate::protocol::versioning::CURRENT_PROTOCOL_VERSION;
pub const STORAGE_REQUIREMENT: crate::core::effects::StorageRequirement =
    crate::core::effects::StorageRequirement::Current(STORAGE_VERSION);

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

    let mut context_fact_ids = Vec::new();
    if input.state == SyncShareState::Upsert {
        context_fact_ids.push(input.owner_fact_id);
        context_fact_ids.extend(input.context_have.iter().copied());
    }
    Intent::new(
        IntentKind::new(SHARE_FACT_WITH_SYNC).expect("valid share_fact_with_sync kind"),
        share_fact_with_sync_key(&input),
        payload.finish(),
    )
    .with_context_fact_ids(context_fact_ids)
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
    if intent.handler_key != share_fact_with_sync_key(&input) {
        return Err("share_fact_with_sync intent key does not match payload".into());
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
    fn handle(&self, raw: &Intent, context: &HandlerContext) -> HandlerResult {
        crate::core::perf_profile::measure_result("share_handler", || {
            let input = decode_share_fact_with_sync(raw)?;
            match input.state {
                SyncShareState::Upsert => {
                    let owner = crate::core::perf_profile::measure_result(
                        "share_context_validate",
                        || {
                            let owner = context.require_fact(&input.owner_fact_id)?;
                            context.require_non_local_fact_bytes(&input.owner_fact_id)?;
                            // Context links came from projector-validated offers. A context fact may
                            // already be purged by the time this queued handler runs.
                            for fact_id in &input.context_have {
                                if context.fact(fact_id).is_some() {
                                    context.require_non_local_fact_bytes(fact_id)?;
                                }
                            }
                            Ok::<_, HandlerError>(owner)
                        },
                    )?;
                    let changed = crate::core::perf_profile::measure_result(
                        "share_record_sync_contribution",
                        || -> Result<bool, HandlerError> {
                            shared_fact::record_sync_contribution_in_tx(
                                context.db(),
                                &input,
                                Some(owner),
                            )
                            .map_err(|err| {
                                HandlerError::fatal(format!("record sync contribution rows: {err}"))
                            })
                        },
                    )?;
                    if changed && !context.is_replay() {
                        crate::core::perf_profile::measure_result("share_live_tail", || {
                            let excluded = crate::protocol::connection::fact_receipt::origin_connection_ids_for_fact(
                                context.db(),
                                input.owner_fact_id,
                            )?
                            .into_iter()
                            .collect::<std::collections::BTreeSet<_>>();
                            seed_connection::advertise_indexed_fact_to_connections_except(
                                context.db(),
                                owner,
                                &excluded,
                            )
                        })
                    } else {
                        Ok(crate::core::effects::RuntimeEffects::new())
                    }
                }
                SyncShareState::Retract => {
                    crate::core::perf_profile::measure_result(
                        "share_record_sync_contribution",
                        || -> Result<bool, HandlerError> {
                            shared_fact::record_sync_contribution_in_tx(context.db(), &input, None)
                                .map_err(|err| {
                                    HandlerError::fatal(format!(
                                        "record sync contribution rows: {err}"
                                    ))
                                })
                        },
                    )?;
                    Ok(crate::core::effects::RuntimeEffects::new())
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::crypto;
    use crate::core::db::Db;
    use crate::core::facts::{Fact, FactScope, ScopeKind};
    use crate::core::intents::{HandlerContext, IntentHandler};
    use crate::core::schema::CORE_SCHEMA_SOURCE;
    use crate::protocol::auth::endpoint::{self as endpoint_rows, fact::EndpointFact};
    use crate::protocol::auth::endpoint_shared::{
        self as endpoint_shared_rows,
        fact::{EndpointDeviceName, EndpointRole, EndpointSharedFact},
    };
    use crate::protocol::connection;
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;

    #[test]
    fn share_fact_with_sync_suppresses_live_tail_to_origin_connection() {
        let store = Db::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
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
        let row = endpoint_rows::local_endpoint_insert(&EndpointFact {
            endpoint: local_endpoint,
            secret: local_secret,
            signing_public_key: crypto::ed25519_public_key(&[13; 32]),
            signing_secret: [13; 32],
        });
        store
            .insert_table_values(vec![row])
            .expect("seed endpoint row");
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
            .write_transaction(|tx| tx.insert_values_in_tx(&endpoint_shared_row).map(|_| ()))
            .expect("seed endpoint shared row");
        for connection_id in [origin_connection_id, other_connection_id] {
            let row = connection::connection::connection_row(
                connection::connection::ConnectionRowFields::without_addresses(
                    connection_id,
                    local_endpoint,
                    remote_endpoint,
                    [8; 32],
                    [12; 32],
                    [13; 32],
                    [14; 32],
                ),
            )
            .expect("connection row");
            store
                .write_transaction(|tx| tx.insert_values_in_tx(&row).map(|_| ()))
                .expect("seed connection row");
        }
        let receipt_row = connection::fact_receipt::connection_fact_receipt_row(
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
        )
        .expect("connection fact receipt row");
        store
            .write_transaction(|tx| tx.insert_values_in_tx(&receipt_row).map(|_| ()))
            .expect("seed receipt row");

        let intent = share_fact_with_sync_intent_for_fact(
            workspace_id,
            owner.id,
            owner.timestamp,
            Vec::new(),
        );
        let output = ShareFactWithSyncHandler::new()
            .handle(
                &intent,
                &HandlerContext::with_facts(&store, [owner.clone()]),
            )
            .expect("share with sync");

        assert_eq!(output.intents.len(), 1);
        let send = connection::send_facts_on_connection::decode_send_facts_on_connection(
            &output.intents[0],
        )
        .expect("send facts intent");
        assert_eq!(send.connection_id, other_connection_id);
        assert_eq!(send.fact_ids, vec![owner.id]);
    }
}
