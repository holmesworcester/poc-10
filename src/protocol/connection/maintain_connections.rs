//! Live connection-maintenance loop.
//!
//! `maintain_connections` keeps the local endpoint connected to peers known
//! from retained facts. It is a live-only recurring intent: replay rebuilds the
//! accepted bootstrap peers from `invite_accepted`, then the daemon fires this
//! loop after the replay barrier to create or retry live connection requests.

use std::collections::BTreeSet;
use std::net::SocketAddr;

use crate::core::effects::PipelineEffects;
use crate::core::intents::{
    HandlerContext, HandlerError, HandlerResult, Intent, IntentHandler, IntentKind, RowMutation,
};
use crate::core::pipeline::RecurringIntentContext;
use crate::core::store::Store;
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
use crate::protocol::connection::send_network_frame::{
    send_network_frame_intent, SendNetworkFrame,
};

pub const MAINTAIN_CONNECTIONS: &str = "maintain_connections";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MaintainConnections {
    created_at_ms: u64,
    local_addr: Option<SocketAddr>,
}

/// Build one maintenance tick, or `None` when there is nothing to maintain.
pub fn build_maintain_connections_intent(
    store: &Store,
    context: RecurringIntentContext,
) -> Result<Option<Intent>, String> {
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
    let local_addr = request::decode::decode_optional_addr(
        addr_block
            .as_slice()
            .try_into()
            .map_err(|_| "maintain_connections addr block is malformed".to_string())?,
    )?;
    let input = MaintainConnections {
        created_at_ms,
        local_addr,
    };
    if intent.key != maintain_connections_key(&input) {
        return Err("maintain_connections idempotence key does not match payload".to_string());
    }
    Ok(input)
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
        let store = context.store()?;
        let mut effects = PipelineEffects::new();

        for pending in pending_connection_requests(store)? {
            effects = effects.local_intent(send_network_frame_intent(SendNetworkFrame {
                routing_key: pending.request_id,
                frame: pending.sealed_request_bytes,
            }));
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
                .row_mutation(RowMutation::PutRow(
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
    store: &Store,
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
    store: &Store,
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
    use crate::core::intents::IntentHandler;
    use crate::core::schema::CORE_SCHEMA_SOURCE;
    use crate::core::store::Store;
    use crate::protocol::auth::endpoint::fact::EndpointFact;
    use crate::protocol::auth::endpoint_shared::fact::EndpointRole;
    use crate::protocol::auth::invite::fact::bootstrap_secret_hash;
    use crate::protocol::auth::{endpoint, invite_accepted};
    use crate::protocol::connection::{ephemeral_secret, request};
    use crate::protocol::registry::FACTS_SCHEMA_SOURCE;

    #[test]
    fn accepted_invite_row_replays_enough_state_to_create_bootstrap_attempt() {
        let store =
            Store::open_memory_with_schema_sources(&[CORE_SCHEMA_SOURCE, FACTS_SCHEMA_SOURCE])
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
        let mut rows = endpoint::endpoint_rows(&local);
        rows.push(
            invite_accepted::invite_accepted_row(accepted_id, &accepted).expect("accepted row"),
        );
        store.insert_table_rows(rows).expect("seed rows");

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
            .handle(&intent, &HandlerContext::new().with_store(&store))
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
        let request = request::decode::open_fact_as_sender(effects.facts[1].body(), &ephemeral)
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
                RowMutation::PutRow(row) if row.table == request::BOOTSTRAP_CONNECTION_ATTEMPT_ROWS
            )
        }));
        assert!(effects.local_intents.is_empty());
    }
}
